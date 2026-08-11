#!/usr/bin/env python3
"""Credential proxy for restricted credentialed CLI execution."""

from __future__ import annotations

import argparse
import base64
import contextlib
import fnmatch
import hmac
import http.client
import io
import json
import logging
import os
import queue
import re
import shlex
import signal
import shutil
import socketserver
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger("credential-proxy")
SLACK_EVENT_QUEUE_MAXSIZE = 1000
SLACK_ERROR_DIAGNOSTIC_FIELDS = ("ok", "error", "needed", "provided")

# GitHub "owner/name" slug validation. Each segment is matched with a single,
# unambiguous character class rather than two adjacent "+" groups around the
# "/" separator, so the match is linear-time and cannot be forced into
# polynomial backtracking (ReDoS). The length guard bounds untrusted input as
# defense-in-depth; 256 is far above real GitHub owner/name limits, so valid
# input is never rejected.
MAX_REPOSITORY_LENGTH = 256
_REPOSITORY_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+")


def is_valid_repository(repository: Any) -> bool:
    """Return True if ``repository`` is a well-formed ``owner/name`` slug."""
    if not isinstance(repository, str) or len(repository) > MAX_REPOSITORY_LENGTH:
        return False
    owner, slash, name = repository.partition("/")
    if not slash:
        return False
    return (
        _REPOSITORY_SEGMENT.fullmatch(owner) is not None
        and _REPOSITORY_SEGMENT.fullmatch(name) is not None
    )


class ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    """HTTP server over a private Unix socket used behind Envoy."""

    daemon_threads = True


class AgentAPIProxyHandler(BaseHTTPRequestHandler):
    """Authenticate the external PlatformAgent API without sharing its key."""

    external_key: str
    upstream_key: str
    upstream_host = "127.0.0.1"
    upstream_port = 8642
    max_request_bytes = 10 * 1024 * 1024
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self._proxy()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy()

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy()

    def _proxy(self) -> None:
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {self.external_key}"
        if not hmac.compare_digest(supplied, expected):
            self.send_error(HTTPStatus.UNAUTHORIZED)
            return
        if self.headers.get("Transfer-Encoding"):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if content_length < 0 or content_length > self.max_request_bytes:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        body = self.rfile.read(content_length) if content_length else None
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower()
            not in {
                "authorization",
                "connection",
                "content-length",
                "host",
                "proxy-authorization",
                "transfer-encoding",
                "upgrade",
            }
        }
        headers["Authorization"] = f"Bearer {self.upstream_key}"
        if body is not None:
            headers["Content-Length"] = str(len(body))

        upstream = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=300
        )
        response_started = False
        try:
            upstream.request(self.command, self.path, body=body, headers=headers)
            response = upstream.getresponse()
            self.send_response(response.status, self._sanitize_header(response.reason))
            for name, value in response.getheaders():
                if name.lower() not in {
                    "connection",
                    "keep-alive",
                    "proxy-authenticate",
                    "transfer-encoding",
                    "upgrade",
                }:
                    self.send_header(
                        self._sanitize_header(name),
                        self._sanitize_header(value),
                    )
            self.send_header("Connection", "close")
            self.end_headers()
            response_started = True
            while chunk := response.read(64 * 1024):
                self.wfile.write(chunk)
                self.wfile.flush()
        except (ConnectionError, TimeoutError, OSError, http.client.HTTPException):
            LOGGER.warning("PlatformAgent API upstream request failed", exc_info=True)
            if not response_started:
                self.send_error(HTTPStatus.BAD_GATEWAY)
            self.close_connection = True
        finally:
            upstream.close()

    @staticmethod
    def _sanitize_header(value: str) -> str:
        """Strip CR/LF so upstream headers cannot split the response (CWE-113)."""
        return value.replace("\r", "").replace("\n", "")

    def log_message(self, message: str, *args: Any) -> None:
        LOGGER.info("agent-api " + message, *args)


class GoogleChatRelay:
    """Credentialed Google Chat/Pub/Sub transport for a credential-free agent."""

    SCOPES = (
        "https://www.googleapis.com/auth/chat.bot",
        "https://www.googleapis.com/auth/pubsub",
    )

    def __init__(self, project_id: str, subscription_name: str) -> None:
        import google.auth
        from google.cloud import pubsub_v1
        from googleapiclient.discovery import build

        credentials, _ = google.auth.default(scopes=self.SCOPES)
        self.subscriber = pubsub_v1.SubscriberClient(credentials=credentials)
        self.subscription_path = (
            subscription_name
            if subscription_name.startswith("projects/")
            else self.subscriber.subscription_path(project_id, subscription_name)
        )
        self.chat = build("chat", "v1", credentials=credentials, cache_discovery=False)
        self._credentials = credentials
        # build() hands the discovery resource a single AuthorizedHttp, and so
        # a single httplib2.Http holding a single TLS socket. httplib2 is not
        # thread safe, and this proxy serves a thread per connection: two
        # concurrent api_call threads interleaving records on that one socket
        # surface as ssl.SSLError, which the handler answers 502. Each call
        # therefore checks out its own transport. A pool rather than a
        # thread-local because request threads are per-connection and the
        # agent-side client opens a connection per call, so thread-locals would
        # mean a fresh TLS handshake to chat.googleapis.com every time.
        self._http_pool: queue.LifoQueue = queue.LifoQueue()
        self._http_pool_size = int(os.getenv("GOOGLE_CHAT_HTTP_POOL_SIZE", "8"))
        self.num_retries = int(os.getenv("GOOGLE_CHAT_API_NUM_RETRIES", "3"))
        self._receipts: dict[str, Any] = {}
        self._lock = threading.Lock()

    def _build_http(self) -> Any:
        import google_auth_httplib2
        from googleapiclient.http import build_http

        return google_auth_httplib2.AuthorizedHttp(
            self._credentials, http=build_http()
        )

    @contextlib.contextmanager
    def _checkout_http(self) -> Any:
        """Lend one authorized transport to a single caller at a time."""
        try:
            http = self._http_pool.get_nowait()
        except queue.Empty:
            http = self._build_http()
        yield http
        # Deliberately not a finally: a transport whose call raised may have
        # failed mid-record, and handing that socket to the next caller would
        # spread one failure across every call after it. It is dropped, and the
        # next checkout builds a clean one.
        if self._http_pool.qsize() < self._http_pool_size:
            self._http_pool.put(http)

    def pull(self, timeout_seconds: int = 20) -> dict[str, Any] | None:
        from google.api_core import retry
        from google.api_core.exceptions import DeadlineExceeded

        try:
            response = self.subscriber.pull(
                request={"subscription": self.subscription_path, "max_messages": 1},
                retry=retry.Retry(deadline=max(timeout_seconds, 1)),
                timeout=max(timeout_seconds, 1),
            )
        except DeadlineExceeded:
            return None
        if not response.received_messages:
            return None
        received = response.received_messages[0]
        receipt = str(uuid.uuid4())
        with self._lock:
            self._receipts[receipt] = received.ack_id
        return {
            "receipt": receipt,
            "data": base64.b64encode(received.message.data).decode("ascii"),
            "attributes": dict(received.message.attributes),
            "messageId": received.message.message_id,
        }

    def settle(self, receipt: str, acknowledge: bool) -> bool:
        with self._lock:
            ack_id = self._receipts.pop(receipt, None)
        if ack_id is None:
            return False
        if acknowledge:
            self.subscriber.acknowledge(
                request={"subscription": self.subscription_path, "ack_ids": [ack_id]}
            )
        else:
            self.subscriber.modify_ack_deadline(
                request={
                    "subscription": self.subscription_path,
                    "ack_ids": [ack_id],
                    "ack_deadline_seconds": 0,
                }
            )
        return True

    def api_call(
        self, resource: list[str], method: str, arguments: dict[str, Any]
    ) -> Any:
        target = self.chat
        for name in resource:
            if not isinstance(name, str) or not name or name.startswith("_"):
                raise ValueError("invalid Google Chat API resource")
            target = getattr(target, name)()
        if not method or method.startswith("_"):
            raise ValueError("invalid Google Chat API method")
        operation = getattr(target, method)(**arguments)
        # num_retries opts into googleapiclient's own jittered backoff, which
        # covers ssl.SSLError, socket timeouts and 5xx. Left at its default of
        # 0 the library attempts the call exactly once. Every Chat method is
        # retried, messages.create included: a duplicate message is a better
        # outcome than a reply the user never sees, and the window in which a
        # retried create duplicates is narrow (the request reached Google and
        # the failure landed on the response).
        with self._checkout_http() as http:
            return operation.execute(http=http, num_retries=self.num_retries)


def _chat_error_fields(exc: Exception) -> dict[str, Any] | None:
    """Return the whitelisted diagnostics a Google Chat API error carried.

    ``None`` means the failure was not an API rejection at all — a transport
    fault, most often — and the caller has nothing to relay beyond the
    exception type. Only the status line crosses this boundary. An HttpError
    stringifies to a message embedding the request URI, and that URI names the
    space and carries the query the relay's own credential authorized, so it is
    never logged nor returned to the agent.
    """
    response = getattr(exc, "resp", None)
    status = getattr(response, "status", None)
    try:
        fields: dict[str, Any] = {"status": int(status)}  # type: ignore[arg-type]
    except (TypeError, ValueError):
        # No parseable status: this runs inside an exception handler, so a
        # second exception here would mask the first.
        return None
    reason = getattr(response, "reason", None)
    if reason:
        fields["reason"] = str(reason)
    return fields


def _slack_error_fields(exc: Exception) -> dict[str, Any] | None:
    """Return the whitelisted diagnostic fields a Slack API error carried.

    ``None`` means the exception carried no payload at all, which is a
    different thing from a payload holding nothing worth relaying — the caller
    distinguishes the two. Only SLACK_ERROR_DIAGNOSTIC_FIELDS cross this
    boundary: the payload is a response body from a call made with the relay's
    own credential, and this value is both logged and returned to the agent.
    """
    response = getattr(exc, "response", None)
    payload = None
    if response is not None:
        if hasattr(response, "data") and isinstance(response.data, dict):
            payload = response.data
        elif hasattr(response, "to_dict"):
            try:
                payload = response.to_dict()
            except Exception:
                payload = None
        elif isinstance(response, dict):
            payload = response
    if not isinstance(payload, dict):
        return None
    return {k: payload[k] for k in SLACK_ERROR_DIAGNOSTIC_FIELDS if k in payload}


def _slack_error_detail(exc: Exception) -> str:
    """Return Slack API error details as a JSON string or fallback text."""
    fields = _slack_error_fields(exc)
    if fields is not None:
        try:
            return json.dumps(fields, sort_keys=True)
        except Exception:
            pass
    response = getattr(exc, "response", None)
    try:
        detail = (
            response.get("error")
            if response is not None and hasattr(response, "get")
            else None
        )
    except Exception:
        detail = None
    return str(detail or "unknown")


class SlackRelay:
    """Credentialed Slack Socket Mode and Web API transport."""

    def __init__(
        self, bot_tokens: str, app_token: str, max_file_bytes: int = 20 * 1024 * 1024
    ) -> None:
        from slack_sdk import WebClient
        from slack_sdk.socket_mode import SocketModeClient

        tokens = [token.strip() for token in bot_tokens.split(",") if token.strip()]
        if not tokens or not app_token:
            raise ValueError("Slack bot and app tokens are required")
        self.max_file_bytes = max_file_bytes
        self.clients: dict[str, Any] = {}
        self.workspaces: list[dict[str, str]] = []
        self.primary_client = None
        for token in tokens:
            client = WebClient(token=token)
            try:
                identity = client.auth_test()
            except Exception as exc:
                LOGGER.error(
                    "Slack bot token authentication failed type=%s error=%s",
                    type(exc).__name__,
                    _slack_error_detail(exc),
                )
                continue
            team_id = str(identity.get("team_id", ""))
            if not team_id:
                LOGGER.error("Slack bot token authentication returned no team ID")
                continue
            if self.primary_client is None:
                self.primary_client = client
            self.clients[team_id] = client
            self.workspaces.append(
                {
                    "teamId": team_id,
                    "teamName": str(identity.get("team", "")),
                    "botUserId": str(identity.get("user_id", "")),
                    "botName": str(identity.get("user", "")),
                }
            )
        if self.primary_client is None:
            raise RuntimeError("no Slack bot token could be authenticated")
        self._events: queue.Queue[dict[str, Any]] = queue.Queue(
            maxsize=SLACK_EVENT_QUEUE_MAXSIZE
        )
        self._receipts: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.socket_client = SocketModeClient(
            app_token=app_token, web_client=self.primary_client
        )
        self.socket_client.socket_mode_request_listeners.append(self._on_event)
        self.socket_client.connect()

    def _on_event(self, client: Any, request: Any) -> None:
        from slack_sdk.socket_mode.response import SocketModeResponse

        client.send_socket_mode_response(
            SocketModeResponse(envelope_id=request.envelope_id)
        )
        event = {
            "type": str(request.type),
            "payload": request.payload,
        }
        try:
            self._events.put_nowait(event)
        except queue.Full:
            LOGGER.warning("Slack event queue is full; dropping event")

    def pull(self, timeout_seconds: int = 20) -> dict[str, Any] | None:
        try:
            event = self._events.get(timeout=max(timeout_seconds, 1))
        except queue.Empty:
            return None
        receipt = str(uuid.uuid4())
        with self._lock:
            self._receipts[receipt] = event
        return {"receipt": receipt, **event}

    def settle(self, receipt: str, acknowledge: bool) -> bool:
        with self._lock:
            event = self._receipts.get(receipt)
            if event is None:
                return False
            if not acknowledge:
                try:
                    self._events.put_nowait(event)
                except queue.Full:
                    LOGGER.warning("Slack event queue is full; cannot requeue event")
                    return False
            del self._receipts[receipt]
            return True

    def bootstrap(self) -> list[dict[str, str]]:
        return self.workspaces

    def _client(self, team_id: str) -> Any:
        return self.clients.get(team_id) or self.primary_client

    def _decode_argument(self, value: Any) -> Any:
        if isinstance(value, list):
            return [self._decode_argument(item) for item in value]
        if isinstance(value, dict):
            if set(value).issubset({"__bytesBase64"}) and "__bytesBase64" in value:
                content = base64.b64decode(value["__bytesBase64"], validate=True)
                if len(content) > self.max_file_bytes:
                    raise ValueError("Slack upload exceeds relay size limit")
                return content
            if "__fileBase64" in value:
                content = base64.b64decode(value["__fileBase64"], validate=True)
                if len(content) > self.max_file_bytes:
                    raise ValueError("Slack upload exceeds relay size limit")
                stream = io.BytesIO(content)
                stream.name = str(value.get("filename", "upload"))
                return stream
            return {key: self._decode_argument(item) for key, item in value.items()}
        return value

    def api_call(
        self, team_id: str, method: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if not method or method.startswith("_"):
            raise ValueError("Slack API method is not available through the relay")
        response = self._client(team_id).api_call(
            method, **self._decode_argument(arguments)
        )
        # SlackResponse defines no keys(), so dict() would fall back to the
        # iterator protocol and raise. The parsed payload lives on .data.
        result = dict(response.data)
        if hasattr(response, "headers") and response.headers:
            WANTED = ("x-oauth-scopes", "x-accepted-oauth-scopes")
            headers = {k: v for k, v in response.headers.items() if k.lower() in WANTED}
            if headers:
                result["__headers"] = headers
        return result

    def download(self, team_id: str, url: str) -> bytes:
        def is_slack_url(value: str) -> bool:
            parsed = urllib.parse.urlparse(value)
            hostname = (parsed.hostname or "").lower()
            return parsed.scheme == "https" and (
                hostname == "slack.com" or hostname.endswith(".slack.com")
            )

        if not is_slack_url(url):
            raise ValueError("Slack file URL must use HTTPS on a slack.com host")

        class SlackRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self,
                request: Any,
                file_pointer: Any,
                code: int,
                message: str,
                headers: Any,
                new_url: str,
            ) -> Any:
                if not is_slack_url(new_url):
                    raise ValueError("Slack file redirect left slack.com")
                return super().redirect_request(
                    request, file_pointer, code, message, headers, new_url
                )

        token = self._client(team_id).token
        request = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {token}"}
        )
        opener = urllib.request.build_opener(SlackRedirectHandler())
        with opener.open(request, timeout=30) as response:
            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type.lower():
                raise ValueError("Slack returned HTML instead of file content")
            content = response.read(self.max_file_bytes + 1)
        if len(content) > self.max_file_bytes:
            raise ValueError("Slack file exceeds relay size limit")
        return content


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern[str]
    message: str


# ------------------------------------------------------------------------------
# Kubernetes read-only enforcement
# ------------------------------------------------------------------------------
#
# RBAC already decides what the agent's Google service account may do in a
# cluster. But RBAC is configured somewhere else by someone else, and until now
# "the agent cannot write to your cluster" was a property of a binding in a
# cluster this repository does not own — not something the proxy could state,
# test, or refuse. A read-only claim nobody enforces at the choke point is a
# claim that survives exactly until one over-broad role grant.
#
# So this gate refuses mutating kubectl at the point every kubectl call already
# passes through, whether or not the cluster would have accepted it. RBAC stays
# the authority; this is the second wall, and it is the one with unit tests.
#
# An allowlist, where GIT_MUTATING_SUBCOMMANDS below is a denylist. That comment
# argues for a denylist because git's read set is open-ended and a read verb
# that failed closed would be worse than the race it closes. kubectl inverts
# both halves: its read set is closed and short, and the cost of missing a write
# verb is a mutated cluster rather than a mutated clone. An unrecognised kubectl
# verb therefore fails closed, and a read verb we forgot is a one-line config
# fix rather than an incident.
#
# Entries with a space are matched as a two-token prefix, which is what lets a
# verb with both read and write subcommands be allowed by half: `rollout status`
# reads, `rollout restart` writes, and `rollout` alone means nothing.
KUBECTL_READ_VERBS = frozenset(
    {
        "get", "describe", "explain", "logs", "top", "events", "diff",
        "api-resources", "api-versions", "version", "cluster-info", "kustomize",
        "wait",
        "auth can-i",
        "config current-context", "config get-clusters", "config get-contexts",
        "config get-users", "config view",
        "rollout history", "rollout status",
    }
)

# Resources refused even under an allowed verb, because reading them *is* the
# credential disclosure the rest of this policy exists to prevent: `kubectl get
# secret -o yaml` returns the same material as the `kubernetes.token-disclosure`
# rule blocks `kubectl create token` for. Compared after `_normalise_resource`,
# so singular, plural and `pod/name` forms all land on the same string.
KUBECTL_DENIED_RESOURCES = frozenset({"secret"})

# kubectl's own global options, split by whether they consume the next argument,
# so the verb scan does not mistake a flag's value for the verb. Same hazard and
# same treatment as `_GIT_GLOBAL_WITH_VALUE` below.
_KUBECTL_GLOBAL_WITH_VALUE = frozenset(
    {
        "-n", "--namespace", "--context", "--cluster", "--user", "--kubeconfig",
        "--as", "--as-group", "--as-uid", "--server", "-s", "--token",
        "--username", "--password", "--client-certificate", "--client-key",
        "--certificate-authority", "--request-timeout", "--tls-server-name",
        "--cache-dir", "--log-file", "--profile", "--profile-output", "-v",
        "--v",
    }
)

# Per-command options that consume a value. Only the resource scan needs these
# — the verb scan has already stopped by the time any of them can appear — so an
# option missing from this set costs at worst a misread resource name, never a
# misread verb.
_KUBECTL_COMMAND_WITH_VALUE = frozenset(
    {
        "-o", "--output", "-l", "--selector", "--field-selector", "-f",
        "--filename", "-c", "--container", "--since", "--since-time", "--tail",
        "--for", "--timeout", "--sort-by", "--template", "--chunk-size",
        "--limit-bytes", "-k", "--kustomize", "--subresource",
    }
)

# Flags refused on every command, allowed verb or not, each for its own reason.
_KUBECTL_FORBIDDEN_FLAGS = {
    "--as": "impersonation",
    "--as-group": "impersonation",
    "--as-uid": "impersonation",
    "--token": "credential override",
    "--server": "API server override",
    "-s": "API server override",
    "--username": "credential override",
    "--password": "credential override",
    "--client-certificate": "credential override",
    "--client-key": "credential override",
    "--certificate-authority": "credential override",
    "--insecure-skip-tls-verify": "TLS verification bypass",
    "--tls-server-name": "TLS verification bypass",
    # `kubectl get --raw /api/v1/namespaces/x/secrets/y` is a bare GET against
    # any path the API server exposes. It reaches every resource without ever
    # naming one, so it walks straight past the resource check below.
    "--raw": "raw API access",
}

_KUBECTL_IMPERSONATION_FLAGS = frozenset({"--as", "--as-group", "--as-uid"})

# The one verb on which impersonation is a read. `kubectl auth can-i --as X`
# issues a SubjectAccessReview asking whether X *could* act; it never acts as X,
# and the answer is the whole point of an RBAC audit. `compliance_audit_sop.md`
# prescribes `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>` as
# the verification step for two of its findings, so refusing impersonation
# everywhere would have broken the audit that exists to find over-broad grants.
_KUBECTL_IMPERSONATION_EXEMPT_VERB = "auth can-i"

_KUBECTL_ALL_NAMESPACES = frozenset({"-A", "--all-namespaces"})

# Verbs whose meaning is only settled by the token after them. Derived from the
# allowlist rather than restated, so adding `rollout pause` in config cannot
# leave the parser reading it as bare `rollout`. A fact about kubectl's grammar,
# not about policy, which is why the parser may read it while staying config
# agnostic in every other respect.
_KUBECTL_COMPOUND_VERBS = frozenset(
    verb.split(" ", 1)[0] for verb in KUBECTL_READ_VERBS if " " in verb
)


def _normalise_resource(token: str) -> str:
    """Fold `pods`, `pod`, `pod/web-1` and `pods.v1.` onto one comparable string.

    Crude singularisation on purpose: both sides of every comparison go through
    this function, so `ingress` folding to `ingres` costs nothing as long as the
    denied set folds the same way.
    """
    token = token.split("/", 1)[0].split(".", 1)[0].lower()
    return token[:-1] if len(token) > 1 and token.endswith("s") else token


@dataclass(frozen=True)
class KubectlPlan:
    """What a kubectl argv asks for, as far as the gate needs to know."""

    verb: str | None
    resources: tuple[str, ...]
    namespaces: tuple[str, ...]
    all_namespaces: bool
    forbidden_flags: tuple[str, ...]


def _kubectl_plan(argv: list[str]) -> KubectlPlan:
    """Read the verb, the resource, the namespaces and the refused flags out of argv.

    kubectl accepts global flags before the verb, so the verb is the first token
    that is not a flag or a flag's value. The resource is the first operand
    after it, comma-split because `kubectl get pods,secrets` is one argument
    naming two.
    """
    forbidden: list[str] = []
    namespaces: list[str] = []
    all_namespaces = False
    verb: str | None = None
    verb_index = len(argv)

    index = 1
    while index < len(argv):
        token = argv[index]
        if not token.startswith("-"):
            verb = token
            verb_index = index
            break
        name, sep, inline = token.partition("=")
        if name in _KUBECTL_FORBIDDEN_FLAGS:
            forbidden.append(name)
        if name in _KUBECTL_ALL_NAMESPACES:
            all_namespaces = True
        if name in {"-n", "--namespace"}:
            if sep:
                namespaces.append(inline)
            elif index + 1 < len(argv):
                namespaces.append(argv[index + 1])
        if name in _KUBECTL_GLOBAL_WITH_VALUE and not sep:
            index += 1
        index += 1

    # A second token joins the verb when the pair is the unit of meaning:
    # `rollout status` reads and `rollout restart` writes. The pair is taken
    # whether or not it is allowed, so a refusal names what was actually run
    # rather than reporting `rollout restart` as "`kubectl rollout` is not
    # read-only", which reads as though the read half were refused too.
    if verb in _KUBECTL_COMPOUND_VERBS:
        following = verb_index + 1
        if following < len(argv) and not argv[following].startswith("-"):
            verb = f"{verb} {argv[following]}"
            verb_index = following

    resources: tuple[str, ...] = ()
    index = verb_index + 1
    while index < len(argv):
        token = argv[index]
        if token.startswith("-"):
            name, sep, inline = token.partition("=")
            if name in _KUBECTL_FORBIDDEN_FLAGS:
                forbidden.append(name)
            if name in _KUBECTL_ALL_NAMESPACES:
                all_namespaces = True
            if name in {"-n", "--namespace"}:
                if sep:
                    namespaces.append(inline)
                elif index + 1 < len(argv):
                    namespaces.append(argv[index + 1])
            if (
                name in _KUBECTL_GLOBAL_WITH_VALUE
                or name in _KUBECTL_COMMAND_WITH_VALUE
            ) and not sep:
                index += 1
            index += 1
            continue
        if not resources:
            resources = tuple(
                _normalise_resource(part) for part in token.split(",") if part
            )
        index += 1

    return KubectlPlan(
        verb=verb,
        resources=resources,
        namespaces=tuple(namespaces),
        all_namespaces=all_namespaces,
        forbidden_flags=tuple(dict.fromkeys(forbidden)),
    )


class KubernetesPolicy:
    """The read-only kubectl gate, and whether it bites or only reports.

    `mode` is `warn` by default and deliberately so. This lands on a fleet whose
    skills nobody has audited command by command, and a gate that starts by
    refusing is a gate that gets switched off after the first false positive.
    Warn runs the command and logs what enforce *would* have refused, which
    turns "is this safe to enforce?" into a question the sidecar logs answer.

    What currently stops enforcing
    ------------------------------
    Two surveys of the repository, one over shell-string command lines and one
    over list-form `subprocess` argv (which the first cannot see, because a list
    has quotes between every token), found this:

    * **One secret read in shipped code.** `agent_common_server.py` runs
      `kubectl get secret platform-agent-secrets -o jsonpath=...` at import to
      resolve `SLACK_BOT_TOKEN`, which this gate refuses. Do not reason about
      it from the KSA's RBAC: that command runs as the GSA like every other
      `kubectl` here, so whether it succeeds today depends on the permission
      set. Enforcing does not change its observable behaviour either way,
      because the bare `except Exception: pass` around it swallows both the
      refusal and the success. The real fix is projecting the token in as an
      env var or a mounted file rather than shelling out for it.

    * **The skill catalogue, which is the real blocker.** A large share of the
      kubectl command lines the skills prescribe are mutating — `gke-multitenancy`
      creates namespaces, `gke-cluster-creation` applies compute classes,
      `gke-batch-hpc` installs Kueue, `gke-upgrades` cordons nodes and patches
      PDBs, `kube-agents-observability` uses `exec` and `port-forward`. Those
      are instructions to a model rather than code, so nothing static refuses
      them; they simply fail at the proxy under enforce. This is warn mode's
      whole reason for existing.

    * **Not a blocker: `platform_mcp_server.apply_manifest` and
      `delete_cluster_manifest`.** They do run `kubectl apply -f` and
      `kubectl delete containercluster`, but they carry no `@mcp.tool()`
      decorator and nothing calls them, so the agent cannot reach them.
      `docs/architecture/06-api-and-data-contracts.md` already records them as
      dead and slates them for removal.

    Note that `apply -f` could not be narrowed by a resource exception even if
    it were wanted — the resource lives in the file, not in argv, so no amount
    of argv analysis can permit "apply, but only ContainerClusters". The way out
    is the harness-v2 direction the rest of Phase 2 takes: change becomes a pull
    request against the GitOps repository rather than a live apply, at which
    point nothing the agent runs needs a write verb and enforce costs nothing.

    Where this gate actually buys enforcement is a `gke-admin` deployment. Do
    not reach for the KSA's read-only RBAC to argue otherwise: as above, kubectl
    here presents the GSA, and it does so against the agent's own cluster too —
    the operator's `CREDENTIAL_PROXY_BOOTSTRAP_COMMAND` builds even the local
    context with `get-credentials`. So on `gke-admin`, where that GSA holds
    `roles/container.admin` project-wide, there is no Kubernetes-side permission
    boundary on the agent's command line at all, on any cluster including this
    one. The only thing standing between the model and a write is the persona.
    This gate turns that into a boundary the sidecar enforces.

    `allowed_verbs` here (`allowedVerbs` in the policy document) is the escape
    hatch, but be aware of two
    things before documenting it as one. It *replaces* the default set rather
    than extending it, so a caller passing `{"apply"}` loses every read verb.
    And on an operator-managed install it is currently unreachable: the policy
    document is rendered from the `credentialProxyPolicyJSON` constant in
    `k8s-operator/internal/controller/platformagent_manifests.go`, which carries
    no `kubernetes` key, and the controller re-applies that ConfigMap on every
    reconcile. Only `CREDENTIAL_PROXY_KUBECTL_MODE` is reachable without a Go
    change, because `mergeCredentialProxyEnv` does not reserve that name.
    """

    RULE_ID = "kubernetes.readonly"

    def __init__(
        self,
        mode: str = "warn",
        allowed_verbs: frozenset[str] = KUBECTL_READ_VERBS,
        denied_resources: frozenset[str] = KUBECTL_DENIED_RESOURCES,
        allowed_namespaces: tuple[str, ...] = (),
    ) -> None:
        if mode not in {"warn", "enforce", "off"}:
            raise ValueError(
                f"kubernetes.mode must be warn, enforce or off, not {mode!r}"
            )
        self.mode = mode
        self.allowed_verbs = allowed_verbs
        self.denied_resources = frozenset(
            _normalise_resource(name) for name in denied_resources
        )
        self.allowed_namespaces = allowed_namespaces

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "KubernetesPolicy":
        """Build the gate from the policy document's optional `kubernetes` key.

        An absent key means the defaults, which are warn mode and no namespace
        restriction — the same posture as a proxy image that predates this gate,
        so an old ConfigMap against a new image changes nothing about what runs.

        `CREDENTIAL_PROXY_KUBECTL_MODE` overrides the document, because flipping
        one deployment to enforce and watching for false refusals should not
        require re-rendering a ConfigMap the operator owns.
        """
        section = payload.get("kubernetes") or {}
        if not isinstance(section, dict):
            raise ValueError("policy `kubernetes` must be an object")

        mode = str(section.get("mode", "warn")).strip().lower()
        override = os.getenv("CREDENTIAL_PROXY_KUBECTL_MODE", "").strip().lower()
        if override:
            mode = override

        verbs = section.get("allowedVerbs")
        allowed = KUBECTL_READ_VERBS if verbs is None else frozenset(verbs)
        resources = section.get("deniedResources")
        denied = (
            KUBECTL_DENIED_RESOURCES if resources is None else frozenset(resources)
        )
        return cls(
            mode=mode,
            allowed_verbs=allowed,
            denied_resources=denied,
            allowed_namespaces=tuple(section.get("allowedNamespaces") or ()),
        )

    def violation(self, argv: list[str]) -> str | None:
        """Why this kubectl command is not read-only, or None if it is.

        Answers the same question in warn and enforce mode; only the caller's
        response to the answer differs. Reported in refusal order — flags first,
        because an impersonated read is a worse finding than a plain write and
        should not be reported as whatever verb it happened to carry.
        """
        if self.mode == "off":
            return None
        if not argv or Path(argv[0]).name != "kubectl":
            return None

        plan = _kubectl_plan(argv)

        forbidden = plan.forbidden_flags
        if plan.verb == _KUBECTL_IMPERSONATION_EXEMPT_VERB:
            forbidden = tuple(
                flag for flag in forbidden if flag not in _KUBECTL_IMPERSONATION_FLAGS
            )
        if forbidden:
            reasons = ", ".join(
                f"{flag} ({_KUBECTL_FORBIDDEN_FLAGS[flag]})" for flag in forbidden
            )
            return (
                f"kubectl {reasons} is refused: these flags change who the "
                "request runs as, where it is sent, or which resource it reads, "
                "none of which the agent chooses."
            )

        if plan.verb is None:
            return "kubectl was called with no subcommand."
        if plan.verb not in self.allowed_verbs:
            return (
                f"`kubectl {plan.verb}` is not a read-only command. The agent "
                "reads cluster state and proposes changes as pull requests; it "
                "does not apply them. Allowed: "
                f"{', '.join(sorted(self.allowed_verbs))}."
            )

        denied = [name for name in plan.resources if name in self.denied_resources]
        if denied:
            return (
                f"`kubectl {plan.verb}` may not read {', '.join(sorted(denied))}: "
                "the response body is the credential itself."
            )

        if self.allowed_namespaces:
            if plan.all_namespaces:
                return (
                    "--all-namespaces is refused: this agent is scoped to "
                    f"{', '.join(self.allowed_namespaces)}."
                )
            outside = [
                namespace
                for namespace in plan.namespaces
                if namespace not in self.allowed_namespaces
            ]
            if outside:
                return (
                    f"namespace {', '.join(outside)} is outside this agent's "
                    f"scope ({', '.join(self.allowed_namespaces)})."
                )
        return None


class Policy:
    def __init__(
        self,
        rules: list[Rule],
        blocked_message: str,
        kubernetes: KubernetesPolicy | None = None,
        forge: ForgePolicy | None = None,
    ) -> None:
        self.rules = rules
        self.blocked_message = blocked_message
        # Built from an empty document rather than defaulted to None, so a
        # Policy assembled in code behaves like one loaded from a file that
        # omits the key — including honouring the env override.
        self.kubernetes = (
            KubernetesPolicy.from_payload({}) if kubernetes is None else kubernetes
        )
        self.forge = ForgePolicy.from_payload({}) if forge is None else forge

    @classmethod
    def load(cls, path: str) -> "Policy":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        blocked_message = payload.get(
            "blockedMessage", "Command blocked for security reasons."
        )
        rules = []
        for item in payload.get("rules", []):
            rules.append(
                Rule(
                    rule_id=item["id"],
                    pattern=re.compile(item["pattern"], re.IGNORECASE | re.MULTILINE),
                    message=item.get("message", blocked_message),
                )
            )
        return cls(
            rules=rules,
            blocked_message=blocked_message,
            kubernetes=KubernetesPolicy.from_payload(payload),
            forge=ForgePolicy.from_payload(payload),
        )

    def blocked_by(self, argv: list[str]) -> Rule | None:
        command = shlex.join(argv)
        return next((rule for rule in self.rules if rule.pattern.search(command)), None)


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool
    timed_out: bool


# A kubeconfig is not passive data. `users[].user.exec.command` runs a program
# here in the sidecar, next to the credentials; `clusters[].cluster.server` and
# `proxy-url` choose where the access token minted by gke-gcloud-auth-plugin is
# sent; `users[].user.tokenFile` reads a file of the author's choosing and sends
# it as the bearer token. The policy engine cannot see any of that, because every
# rule it holds matches on argv and the argv is only ever `kubectl get pods`.
#
# The agent can write anywhere in the shared workspace, so any kubeconfig it
# names is a document it controls. Rather than validate that document — a
# denylist over a format that keeps growing, and racy besides, since the file can
# be rewritten between the check and the open — the proxy reads exactly one
# string out of it and regenerates the rest. See CommandExecutor._resolve_kubeconfig.
_GKE_CONTEXT_COMPONENT = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# Enough for any real kubeconfig; the point is that this file is attacker-chosen
# and gets read into memory before anything is known about it.
MAX_KUBECONFIG_BYTES = 1 << 20


@dataclass(frozen=True)
class ClusterTarget:
    """A GKE cluster identified well enough to re-fetch credentials for it."""

    project: str
    location: str
    cluster: str

    @property
    def context_name(self) -> str:
        return f"gke_{self.project}_{self.location}_{self.cluster}"


def parse_gke_context(context: str) -> ClusterTarget | None:
    """Recover the cluster triple from a `gke_<project>_<location>_<cluster>` name.

    This is the same convention the operator builds in `buildCredentialProxyEnv`
    and the Cluster Agent preflight compares against, and it is what makes the
    regeneration below possible: the context name alone says which cluster to ask
    Google for. Underscores are the separator and none of the three components may
    contain one, so a 4-way split is unambiguous.

    Each component is held to the GKE naming rules, which is also what keeps the
    value safe to use in a filename — no separators, no dots, no traversal.
    """
    parts = context.split("_", 3)
    if len(parts) != 4 or parts[0] != "gke":
        return None
    project, location, cluster = parts[1], parts[2], parts[3]
    if not all(_GKE_CONTEXT_COMPONENT.match(part) for part in (project, location, cluster)):
        return None
    return ClusterTarget(project=project, location=location, cluster=cluster)


def _is_get_credentials(argv: list[str]) -> bool:
    """Is this the one command that legitimately authors a kubeconfig?

    Matched on the subcommand sequence rather than on position, so global flags
    may appear anywhere ahead of it.
    """
    if not argv or argv[0] != "gcloud":
        return False
    try:
        index = argv.index("container")
    except ValueError:
        return False
    return argv[index + 1 : index + 3] == ["clusters", "get-credentials"]


def read_current_context(text: str) -> str | None:
    """Read `current-context` out of a kubeconfig the way kubectl would.

    `yaml.safe_load`, deliberately, and never `yaml.CSafeLoader`. The C loader
    recurses in C: a deeply nested document takes the whole sidecar down with
    SIGSEGV, where the pure-Python loader raises a catchable `RecursionError`.
    This input is chosen by the agent, so that is the difference between one
    rejected request and a dead credential proxy. `safe_load` picks the Python
    loader on its own; the point of saying so is that switching it would be a
    denial-of-service, not an optimisation.

    Alias expansion is not a concern here. PyYAML resolves every reference to an
    anchor to the same node and caches the object built from it, so a
    billion-laughs document costs memory proportional to its own size rather
    than to its nominal expansion.

    Anything else — a syntax error, several documents, a top level that is not a
    mapping, a non-string `current-context` — reads as absent, and the caller
    turns that into a rejection.
    """
    import yaml  # lazy: keeps the module importable without pyyaml, as elsewhere in this directory

    try:
        document = yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        return None
    if not isinstance(document, dict):
        return None
    context = document.get("current-context")
    if not isinstance(context, str):
        return None
    return context.strip() or None


# Identity stamped on commits the proxy makes on the agent's behalf. `git commit`
# exits 128 — "Please tell me who you are" — with no identity configured, and the
# commit runs here rather than in the agent container, so a .gitconfig over there
# would never be read. The address uses the reserved `.invalid` TLD (RFC 2606) so
# an automated commit can never be attributed to a real mailbox that happens to
# exist. Both are overridable per deployment.
DEFAULT_GIT_AUTHOR_NAME = "kube-agents platform agent"
DEFAULT_GIT_AUTHOR_EMAIL = "platform-agent@kube-agents.invalid"

# The marker `gitops_workspace` drops in a leased workspace. The two names must
# agree: renaming one without the other locks every skill out of git.
GIT_LEASE_MARKER = ".lease"

# git subcommands that write a working tree or a remote ref. Anything here is
# refused unless it runs inside a leased workspace, because the pod runs many
# agents against one shared volume and these are the verbs with which one agent
# destroys another's work — the incident that prompted the rule was
# `submit-suggestion` running `checkout -b` and `push -f` inside the clone a
# fleet audit was midway through.
#
# A denylist rather than a read-only allowlist, deliberately. The set of verbs
# that can mutate a tree is closed and well known; the set of read verbs is not,
# and a new one silently failing closed would be a worse outcome than the race
# this closes. `clone` is absent on purpose: it runs at the lease root, one
# directory above the tree it is about to create, and it cannot damage a tree
# that does not exist yet. `fetch` is absent for the same reason it is safe —
# it writes remote-tracking refs and nothing in the working tree. `config`,
# `remote` and every read verb are likewise untouched.
#
# `pull`, `submodule` and `sparse-checkout` are here because each one is a
# working-tree write wearing another word: `pull` is `fetch` plus the `merge`
# or `rebase` two lines up, `submodule update` checks out whole directories,
# and `sparse-checkout set` adds and removes files across the entire tree. All
# three were reachable in a clone another agent was midway through.
GIT_MUTATING_SUBCOMMANDS = frozenset(
    {
        "add", "am", "apply", "branch", "checkout", "cherry-pick", "clean",
        "commit", "merge", "mv", "pull", "push", "rebase", "reset", "restore",
        "revert", "rm", "sparse-checkout", "stash", "submodule", "switch",
        "tag", "update-ref", "worktree",
    }
)

# git's own global options, split by whether they consume the next argument.
# Needed to find the subcommand in `git --literal-pathspecs add …` (which
# audit_report issues) without mistaking a flag for a verb.
_GIT_GLOBAL_WITH_VALUE = frozenset(
    {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix"}
)


def _git_plan(argv: list[str]) -> tuple[str | None, list[str], int]:
    """The subcommand in `argv`, every directory its `-C` flags select, and where it sat.

    `-C` is returned rather than ignored because git applies it cumulatively
    before running the subcommand: `git -C /elsewhere commit` executes nowhere
    near the working directory the caller reported, so a containment check that
    only looked at `cwd` would be checking the wrong path.

    The index is returned so a caller that has to keep reading past the
    subcommand — `_git_push_plan` does, to find the refspecs — does not have to
    repeat this scan and risk disagreeing with it about which token the
    subcommand was.
    """
    directories: list[str] = []
    index = 1
    while index < len(argv):
        token = argv[index]
        if not token.startswith("-"):
            return token, directories, index
        name, sep, inline = token.partition("=")
        if name == "-C":
            if sep:
                directories.append(inline)
            elif index + 1 < len(argv):
                directories.append(argv[index + 1])
        if name in _GIT_GLOBAL_WITH_VALUE and not sep:
            index += 1
        index += 1
    return None, directories, len(argv)


# ------------------------------------------------------------------------------
# The forge gate: branch and pull request, and nothing else
# ------------------------------------------------------------------------------
#
# The agent holds a repository-scoped GitHub App installation token, minted by
# Minty and cached into `gh` and the git credential store by
# `github_token_refresh.py`. Everything that token can do, the agent can do —
# and an installation token with `contents: write` and `pull_requests: write`
# can merge its own pull request, force-push over `main`, delete a branch and
# approve a review. The persona says the agent proposes changes rather than
# making them. Nothing until now made that true.
#
# `GIT_MUTATING_SUBCOMMANDS` above is about the local filesystem: it stops one
# agent trampling another's working tree. A push that is perfectly well-behaved
# inside its own lease can still land on `main`. This gate is about the remote,
# and it asks a different question of each tool.
#
# For `gh`: which command is this? An allowlist, for the same reason
# `KUBECTL_READ_VERBS` is one rather than the reason `GIT_MUTATING_SUBCOMMANDS`
# is not. `gh`'s surface grows with every release — `ruleset`, `cache`,
# `attestation` and `org` all arrived after this repository was started — and a
# subcommand nobody has classified should fail closed rather than inherit "not
# on the denylist" as permission.
#
# For `git push`: where does it land? Not an allowlist of verbs; `push` is the
# only remote-write verb git has, so refusing it would refuse the entire point.
# The check is on the destination refspec instead.
#
# Force is deliberately not refused. `submit_suggestion.push_branch` explains at
# length why it pushes `--force-with-lease`: a pull request that comes back for
# another round of review has to update the branch it already points at. What
# makes a force dangerous at fleet scale is where it lands, and that is what is
# checked here.

# `gh` commands the agent may run, as space-joined prefixes matched the same way
# `KUBECTL_READ_VERBS` matches: an entry with a space is a two-token prefix, so
# a command with both a read and a write half can be allowed by half.
#
# The write half of this set is the branch-and-pull-request path and nothing
# else. What is deliberately absent is worth stating, because each omission is a
# decision rather than an oversight:
#
#   * `pr merge` — the whole point. A proposal the proposer can accept is not a
#     proposal.
#   * `pr review` — self-approval is merging with extra steps on any repository
#     whose branch protection counts approvals.
#   * `pr checkout` — a working-tree write that would go around the lease gate,
#     which only knows how to read `git` argv.
#   * `repo` beyond `view` — delete, rename, archive, edit and `set-default`
#     are repository administration; `fork` and `clone` are `git clone`'s job,
#     inside a lease.
#   * `workflow run|enable|disable` and `run rerun|cancel|delete` — dispatching
#     CI is arbitrary code execution wearing a different hat. This repository's
#     App is not scoped for it today (`actions: write` is not among the three
#     permissions in `config/integrations/github/configmap.yaml.template`), so
#     the refusal costs nothing now and is here for the install that widens the
#     scope without revisiting this file.
#   * `secret`, `variable`, `ssh-key`, `gpg-key`, `auth` beyond `status`,
#     `extension`, `alias`, `config` — credential and tool self-modification,
#     already half-covered by the regex rules in the policy document and covered
#     properly here. `secret` is in the same position as `workflow run`: the App
#     has no `secrets: write` today either.
#
# Matching is on the literal argv, so a `gh` alias is refused whether or not it
# expands to something allowed — including the built-in `co` for `pr checkout`,
# which is refused twice over. Resolving aliases would mean reading `gh`'s
# config, and this gate deliberately decides from the command line alone.
#
# `label create` is the one repository-configuration write in the set, and it is
# here because two shipped skills open with it: `audit_report.ensure_labels` and
# `resolver.ensure_labels_exist` both create the status labels they are about to
# apply. Creating a label the agent then puts on its own issue is part of the
# proposal, not administration of the repository.
GH_ALLOWED_COMMANDS = frozenset(
    {
        "api",
        "auth status",
        "issue close", "issue comment", "issue create", "issue edit",
        "issue list", "issue reopen", "issue status", "issue view",
        "label create", "label list",
        "pr checks", "pr close", "pr comment", "pr create", "pr diff",
        "pr edit", "pr list", "pr ready", "pr reopen", "pr status", "pr view",
        "release list", "release view",
        "repo view",
        "run list", "run view",
        "search",
        "status",
        "version",
        "workflow list", "workflow view",
    }
)

# Branches a push may not land on, as `fnmatch` patterns matched case-folded
# against the ref with `refs/heads/` stripped. Deliberately the same three names
# as `submit_suggestion.PROTECTED_BRANCHES` and `audit_report.PROTECTED_BRANCHES`,
# which have refused these targets at the skill layer for as long as the skills
# have existed: `main` and `master` are the GitOps rollout branches and
# `production` is the convention some fleets use instead. Two layers refusing
# different lists would be worse than either — the question "which one applies?"
# has no useful answer. What the proxy adds is that the agent cannot get past it
# by running `git` itself instead of the skill.
GIT_PROTECTED_BRANCHES = ("main", "master", "production")

# `gh`'s own options, split by whether they consume the next argument, so the
# command scan does not read a flag's value as the command. Same hazard and
# same treatment as `_KUBECTL_GLOBAL_WITH_VALUE` and `_GIT_GLOBAL_WITH_VALUE`.
_GH_GLOBAL_WITH_VALUE = frozenset({"-R", "--repo", "--hostname"})

# Derived, not restated, for the reason `_KUBECTL_COMPOUND_VERBS` is derived:
# adding `pr merge` to the allowlist in config must not leave the parser
# reading `gh pr merge` as bare `gh pr`.
_GH_COMPOUND_COMMANDS = frozenset(
    command.split(" ", 1)[0] for command in GH_ALLOWED_COMMANDS if " " in command
)

# `gh api` flags that turn a GET into a POST. gh's own rule, not a policy
# choice: any `--field`/`--raw-field`/`--input` switches the default method, so
# `gh api repos/o/r/issues -f title=x` files an issue while looking like a read.
# Scoped to `api` on purpose — `-F` means `--body-file` to `gh issue comment`.
_GH_API_FIELD_FLAGS = frozenset({"-f", "--raw-field", "-F", "--field", "--input"})
_GH_API_READ_METHODS = frozenset({"GET", "HEAD"})

# `git push` options that consume the next argument. `--force-with-lease` is
# absent because its value is only ever `=`-attached; taking the following token
# would swallow the remote.
_GIT_PUSH_WITH_VALUE = frozenset(
    {"--repo", "-o", "--push-option", "--receive-pack", "--exec"}
)
_GIT_PUSH_DELETE_FLAGS = frozenset({"-d", "--delete"})
_GIT_PUSH_DRY_RUN_FLAGS = frozenset({"-n", "--dry-run"})

# Flags that push refs the argv never names. `--all` pushes every local branch,
# which on a workspace that ran `checkout -B` from `origin/main` includes `main`;
# `--mirror` does that and deletes every remote ref with no local counterpart.
# Neither can be checked against a destination, because neither states one.
_GIT_PUSH_BROADCAST_FLAGS = frozenset({"--all", "--mirror"})


@dataclass(frozen=True)
class GhPlan:
    """What a `gh` argv asks for, as far as the gate needs to know."""

    command: str | None
    display: str
    api_method: str | None
    api_fields: bool
    api_endpoint: str | None


def _gh_plan(argv: list[str]) -> GhPlan:
    """Read the command out of a `gh` argv, plus what `gh api` would do with it.

    `command` is what the allowlist is matched against; `display` is the first
    two operands whether or not the first is a compound. They differ so that a
    refusal can name what was actually run: `gh secret set` is refused on
    `secret`, but reporting it as "`gh secret` is not allowed" invites the reply
    that `gh secret list` is harmless, which is true and beside the point.
    """
    operands: list[str] = []
    method: str | None = None
    fields = False

    index = 1
    while index < len(argv):
        token = argv[index]
        if not token.startswith("-"):
            # Every operand is walked past, but only the first two are kept:
            # the scan cannot stop at the command, because `gh api <endpoint>
            # -X DELETE` puts the flag that decides the verdict after it.
            if len(operands) < 2:
                operands.append(token)
            index += 1
            continue
        name, sep, inline = token.partition("=")
        if name in _GH_API_FIELD_FLAGS:
            fields = True
        if name in {"-X", "--method"}:
            if sep:
                method = inline
            elif index + 1 < len(argv):
                method = argv[index + 1]
        if (
            name in _GH_GLOBAL_WITH_VALUE
            or name in _GH_API_FIELD_FLAGS
            or name in {"-X", "--method"}
        ) and not sep:
            index += 1
        index += 1

    if not operands:
        return GhPlan(
            command=None,
            display="",
            api_method=method,
            api_fields=fields,
            api_endpoint=None,
        )

    command = operands[0]
    if command in _GH_COMPOUND_COMMANDS and len(operands) > 1:
        command = " ".join(operands[:2])
    return GhPlan(
        command=command,
        display=" ".join(operands),
        api_method=method,
        api_fields=fields,
        api_endpoint=operands[1] if operands[0] == "api" and len(operands) > 1 else None,
    )


@dataclass(frozen=True)
class GitPushPlan:
    """Where a `git push` argv would land, as far as the gate needs to know."""

    destinations: tuple[str, ...]
    deletions: tuple[str, ...]
    broadcast_flags: tuple[str, ...]
    dry_run: bool


def _normalise_ref(ref: str) -> str:
    """`+refs/heads/main` and `main` are the same destination; say so once."""
    ref = ref.lstrip("+")
    for prefix in ("refs/heads/",):
        if ref.startswith(prefix):
            return ref[len(prefix) :]
    return ref


def _git_push_plan(argv: list[str]) -> GitPushPlan | None:
    """Read the destinations out of a `git push` argv, or None if it is not one.

    The first operand after `push` is the repository and every operand after
    that is a refspec, which is why the remote is skipped rather than examined:
    a push is dangerous because of the ref it moves, not the remote it moves it
    on, and the remote may be a URL that names no ref at all.

    A refspec's destination is the half after the colon, or the whole thing when
    there is no colon — `git push origin topic` means `topic:topic`. An empty
    source half is a deletion: `git push origin :main` removes `main`, which is
    the same argv shape as pushing to it with one character missing.

    `--repo=<remote>` supplies the repository in place of the operand, so with it
    every operand is a refspec and none of them is the remote. Nothing shipped
    uses that form, but skipping an operand that is really a refspec would read
    `git push --repo=origin main` as a push with no refspec at all.
    """
    subcommand, _, index = _git_plan(argv)
    if subcommand != "push":
        return None

    operands: list[str] = []
    deletion_flag = False
    dry_run = False
    broadcast: list[str] = []
    remote_in_flag = False

    index += 1
    while index < len(argv):
        token = argv[index]
        if not token.startswith("-"):
            operands.append(token)
            index += 1
            continue
        name, sep, _ = token.partition("=")
        if name in _GIT_PUSH_DELETE_FLAGS:
            deletion_flag = True
        if name in _GIT_PUSH_DRY_RUN_FLAGS:
            dry_run = True
        if name in _GIT_PUSH_BROADCAST_FLAGS:
            broadcast.append(name)
        if name == "--repo":
            remote_in_flag = True
        if name in _GIT_PUSH_WITH_VALUE and not sep:
            index += 1
        index += 1

    destinations: list[str] = []
    deletions: list[str] = []
    for refspec in operands if remote_in_flag else operands[1:]:
        source, separator, target = refspec.partition(":")
        if not separator:
            source, target = refspec, refspec
        if deletion_flag or (separator and not source):
            deletions.append(_normalise_ref(target or source))
        else:
            destinations.append(_normalise_ref(target))

    return GitPushPlan(
        destinations=tuple(destinations),
        deletions=tuple(deletions),
        broadcast_flags=tuple(dict.fromkeys(broadcast)),
        dry_run=dry_run,
    )


@dataclass(frozen=True)
class ForgeViolation:
    """A refusal, carrying the rule id the response should name."""

    rule_id: str
    message: str


class ForgePolicy:
    """The branch-and-pull-request gate, and whether it bites or only reports.

    Shares `KubernetesPolicy`'s three modes and its reasoning about them: `warn`
    runs the command and logs what `enforce` would have refused, so "is this
    safe to enforce?" becomes a question the sidecar logs answer rather than one
    the first false positive answers by getting the gate switched off.

    Unlike that gate, this one ships enforcing. The difference is what the
    survey found. kubectl's allowlist collides with a large share of the skill
    catalogue, because the catalogue is full of instructions to apply, patch and
    cordon. This one collides with nothing that reaches it. Every `gh` call in
    shipped code — `audit_report`, `resolver`, `submit_suggestion` — is a list,
    view, create, edit, comment, close or `label create`, and every `git push`
    names its branch (`push --force-with-lease origin <branch>` in
    `submit_suggestion`, `push -f origin <branch>` in `audit_report`). A gate
    that refuses nothing anybody does is a gate that can start refusing.

    The one apparent collision is `github_token_refresh.refresh_git_credentials`,
    which runs `gh auth login --with-token` and `gh auth setup-git` — both
    refused here, and both unreachable from the agent. When
    `CREDENTIAL_PROXY_URL` is set, which it is in the agent container, that
    function POSTs to `/v1/github/refresh` and returns before it gets there; the
    `gh` calls run in the sidecar, where the handler executes the script
    directly rather than through `/v1/exec`. The `gcloud auth
    print-identity-token` two lines above them proves the path is exempt
    already: the `gcp.access-token-disclosure` rule would refuse it otherwise.

    Two refusals are worth knowing about before they are met:

    * **`git push` with no refspec.** Refused, not allowed. `git push` and
      `git push origin` land wherever `push.default` and the current branch send
      them, and the gate cannot say where that is without reading `.git/HEAD`
      — which would be both a departure from argv-structural checking and racy,
      since the agent can move HEAD between the check and the push. Naming the
      branch is one word and makes the destination checkable.

    * **`gh api graphql`.** Refused, because GraphQL is POST-only and carries
      its query in `-f query=…`, which is indistinguishable in argv from
      `-f title=…` on an issue. No shipped skill uses it; a read that needs it
      should use the REST path the rest of the catalogue uses.

    `allowedCommands` and `protectedBranches` in the policy document are the
    escape hatches, with the same two caveats as `allowedVerbs`: each *replaces*
    its default rather than extending it, and neither is reachable on an
    operator-managed install, because `credentialProxyPolicyJSON` in
    `k8s-operator/internal/controller/platformagent_manifests.go` carries no
    `forge` key and the controller re-applies that ConfigMap every reconcile.
    `CREDENTIAL_PROXY_FORGE_MODE` is reachable, which is what matters for
    turning the gate off in a hurry.
    """

    GH_RULE_ID = "github.write-path"
    GIT_RULE_ID = "git.push-target"

    def __init__(
        self,
        mode: str = "enforce",
        allowed_commands: frozenset[str] = GH_ALLOWED_COMMANDS,
        protected_branches: tuple[str, ...] = GIT_PROTECTED_BRANCHES,
    ) -> None:
        if mode not in {"warn", "enforce", "off"}:
            raise ValueError(f"forge.mode must be warn, enforce or off, not {mode!r}")
        self.mode = mode
        self.allowed_commands = allowed_commands
        self.protected_branches = protected_branches

    @property
    def enforcing(self) -> bool:
        return self.mode == "enforce"

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ForgePolicy":
        """Build the gate from the policy document's optional `forge` key.

        An absent key means the defaults, which enforce. That is the one place
        this differs from `KubernetesPolicy.from_payload`, where an absent key
        means warn: an old ConfigMap against a new proxy image starts refusing
        `gh pr merge` immediately, on purpose, because nothing in the tree runs
        it.
        """
        section = payload.get("forge") or {}
        if not isinstance(section, dict):
            raise ValueError("policy `forge` must be an object")

        mode = str(section.get("mode", "enforce")).strip().lower()
        override = os.getenv("CREDENTIAL_PROXY_FORGE_MODE", "").strip().lower()
        if override:
            mode = override

        commands = section.get("allowedCommands")
        allowed = GH_ALLOWED_COMMANDS if commands is None else frozenset(commands)
        branches = section.get("protectedBranches")
        protected = (
            GIT_PROTECTED_BRANCHES if branches is None else tuple(branches)
        )
        return cls(
            mode=mode, allowed_commands=allowed, protected_branches=protected
        )

    def _protects(self, ref: str) -> bool:
        # Case-folded because the skill-layer check is, and because a fleet that
        # calls its trunk `Main` should not have to discover the difference.
        folded = ref.lower()
        return any(
            fnmatch.fnmatch(folded, pattern.lower())
            for pattern in self.protected_branches
        )

    def violation(self, argv: list[str]) -> ForgeViolation | None:
        """Why this command is not a branch-or-pull-request write, or None if it is."""
        if self.mode == "off" or not argv:
            return None
        executable = Path(argv[0]).name
        if executable == "gh":
            return self._gh_violation(argv)
        if executable == "git":
            return self._git_violation(argv)
        return None

    def _gh_violation(self, argv: list[str]) -> ForgeViolation | None:
        plan = _gh_plan(argv)
        if plan.command is None:
            return None  # `gh --version` and friends run nothing against a repo.
        if plan.command not in self.allowed_commands:
            return ForgeViolation(
                self.GH_RULE_ID,
                f"`gh {plan.display}` is not on the branch-and-pull-request "
                "path. The agent proposes changes and comments on them; it does "
                "not merge, approve, administer a repository or dispatch CI. "
                f"Allowed: {', '.join(sorted(self.allowed_commands))}.",
            )
        if plan.command != "api":
            return None

        if (plan.api_endpoint or "").strip().lower() == "graphql":
            # Refused by name rather than left to the method and field rules
            # below. Those catch the normal spelling, but GraphQL puts the verb
            # inside `query=`, where nothing in the argv can see it: `-X GET -f
            # query=mutation{...}` reads as a query parameter and passes. The
            # endpoint has no read-only shape to allow, so there is nothing lost
            # in refusing all of it.
            return ForgeViolation(
                self.GH_RULE_ID,
                "`gh api graphql` is refused: a GraphQL mutation and a GraphQL "
                "query are the same command line, distinguished only inside the "
                "query text. Use the REST endpoints, which say in the argv what "
                "they do.",
            )

        method = (plan.api_method or "").strip().upper()
        if method and method not in _GH_API_READ_METHODS:
            return ForgeViolation(
                self.GH_RULE_ID,
                f"`gh api --method {method}` is refused: `gh api` is allowed as a "
                "read, and any other method reaches the whole GitHub API with the "
                "agent's token, past every other rule here.",
            )
        if not method and plan.api_fields:
            return ForgeViolation(
                self.GH_RULE_ID,
                "`gh api` with a field flag is refused: a field switches gh's "
                "default method from GET to POST, so this writes. Add `--method "
                "GET` if the field really is a query parameter.",
            )
        return None

    def _git_violation(self, argv: list[str]) -> ForgeViolation | None:
        plan = _git_push_plan(argv)
        if plan is None or plan.dry_run:
            return None

        if plan.broadcast_flags:
            return ForgeViolation(
                self.GIT_RULE_ID,
                f"`git push {' '.join(plan.broadcast_flags)}` is refused: it "
                "pushes refs this command line does not name, which on a "
                "workspace branched from the default branch includes that "
                "branch. Push the one branch by name.",
            )
        if plan.deletions:
            return ForgeViolation(
                self.GIT_RULE_ID,
                f"deleting remote {', '.join(sorted(plan.deletions))} is refused: "
                "the agent adds branches and pull requests, and removing them is "
                "the reviewer's decision, taken by merging or closing.",
            )
        protected = sorted(
            {ref for ref in plan.destinations if self._protects(ref)}
        )
        if protected:
            return ForgeViolation(
                self.GIT_RULE_ID,
                f"pushing to {', '.join(protected)} is refused: it is a "
                "protected branch, and a change that lands on it directly is a "
                "change nobody reviewed. Push a branch and open a pull request.",
            )
        if not plan.destinations:
            return ForgeViolation(
                self.GIT_RULE_ID,
                "`git push` with no refspec is refused: where it lands depends "
                "on the current branch and `push.default`, which this command "
                "line does not say. Name it — `git push origin <branch>`.",
            )
        return None


class CommandExecutor:
    ALLOWED_EXECUTABLES = ("gcloud", "kubectl", "gh", "git")

    def __init__(
        self, timeout_seconds: int, max_output_bytes: int, state_dir: str
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.state_dir = Path(state_dir)
        self.home_dir = self.state_dir / "home"
        self.workspace_dir = Path(
            os.getenv("CREDENTIAL_PROXY_WORKSPACE_ROOT", str(self.state_dir / "workspace"))
        ).resolve()
        # On by default; the escape hatch exists so an operator can unblock a
        # skill that has not been migrated to leases yet without shipping a new
        # image. See `git_lease_violation`.
        self.require_git_lease = os.getenv(
            "CREDENTIAL_PROXY_REQUIRE_GIT_LEASE", "1"
        ).strip().lower() not in {"0", "false", "no", "off"}
        self.tmp_dir = self.state_dir / "tmp"
        self.config_dir = self.home_dir / ".config"
        self.cache_dir = self.home_dir / ".cache"
        self.local_state_dir = self.home_dir / ".local" / "state"
        self.kube_dir = self.home_dir / ".kube"
        # Every kubeconfig any agent-selected command actually reads lives here.
        # It has to be under the state dir: that is a sidecar-only emptyDir
        # (`credential-proxy-state` in platformagent_manifests.go), whereas the
        # workspace is the PVC the agent writes to. Keeping the file out of the
        # agent's reach is what removes the rewrite-after-check race — there is
        # no window in which the document can change between validation and use,
        # because the agent never had a handle on the document at all.
        self.kubeconfig_dir = self.state_dir / "kubeconfigs"
        for path in (
            self.home_dir,
            self.workspace_dir,
            self.tmp_dir,
            self.config_dir,
            self.cache_dir,
            self.local_state_dir,
            self.kube_dir,
            self.kubeconfig_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)
        # Serialises the `get-credentials` that fills a cache miss. Generation is
        # rare and the server is threaded, so a single lock is cheaper than the
        # bookkeeping needed to make it per-cluster.
        self._kubeconfig_lock = threading.Lock()
        trusted_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        self.executables = {
            name: shutil.which(name, path=trusted_path)
            for name in self.ALLOWED_EXECUTABLES
        }
        self.environment = {
            "PATH": trusted_path,
            "HOME": str(self.home_dir),
            "TMPDIR": str(self.tmp_dir),
            "XDG_CONFIG_HOME": str(self.config_dir),
            "XDG_CACHE_HOME": str(self.cache_dir),
            "XDG_STATE_HOME": str(self.local_state_dir),
            "CLOUDSDK_CONFIG": str(self.config_dir / "gcloud"),
            "GH_CONFIG_DIR": str(self.config_dir / "gh"),
            "KUBECONFIG": str(self.home_dir / ".kube" / "config"),
            "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        }
        # Forward only variables required by supported credential clients. Chat
        # tokens and proxy control variables must never enter an agent-selected
        # subprocess, even though that subprocess runs in the sidecar.
        for name in (
            "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "LANG",
            "LC_ALL",
            "TOKEN_BROKER_URL",
            "KSA_TOKEN_FILE",
        ):
            if name in os.environ:
                self.environment[name] = os.environ[name]
        # Applied per invocation in `_execute`, and only to git, rather than
        # written once to ~/.gitconfig: the identity then stays scoped to the
        # proxied commands that need it and leaves no ambient state in the
        # sidecar's home for anything else to pick up. An operator who sets the
        # override to an empty string means "unset", not "commit with no name",
        # so an empty value falls back rather than reinstating the exit 128.
        author_name = (
            os.getenv("CREDENTIAL_PROXY_GIT_AUTHOR_NAME", "").strip() or DEFAULT_GIT_AUTHOR_NAME
        )
        author_email = (
            os.getenv("CREDENTIAL_PROXY_GIT_AUTHOR_EMAIL", "").strip() or DEFAULT_GIT_AUTHOR_EMAIL
        )
        self.git_identity = {
            "GIT_AUTHOR_NAME": author_name,
            "GIT_AUTHOR_EMAIL": author_email,
            "GIT_COMMITTER_NAME": author_name,
            "GIT_COMMITTER_EMAIL": author_email,
        }

    def bootstrap(self, command: str) -> None:
        """Prepare the trusted shell profile without interpreting later commands."""
        if not command.strip():
            return
        bootstrap_environment = self.environment.copy()
        for name in (
            "GKE_PROJECT_ID",
            "GKE_CLUSTER_NAME",
            "GKE_LOCATION",
            "KUBE_CONTEXT_NAME",
            "KUBE_DEFAULT_NAMESPACE",
        ):
            if name in os.environ:
                bootstrap_environment[name] = os.environ[name]
        result = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-c", command],
            cwd=self.workspace_dir,
            env=bootstrap_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=max(self.timeout_seconds, 120),
        )
        if result.returncode != 0:
            # The command's output is the only useful diagnostic when the
            # bootstrap fails, but it must not travel with the exception, which
            # can surface outside the sidecar. Log it here instead, where only an
            # operator reading the sidecar's own logs sees it, and leave the
            # message itself output-free.
            stdout_bytes, stdout_truncated = self._truncate(result.stdout)
            stderr_bytes, stderr_truncated = self._truncate(result.stderr)
            LOGGER.error(
                "credential proxy shell bootstrap failed with exit code %s\n"
                "bootstrap stdout%s:\n%s\nbootstrap stderr%s:\n%s",
                result.returncode,
                " (truncated)" if stdout_truncated else "",
                stdout_bytes.decode("utf-8", errors="replace").strip(),
                " (truncated)" if stderr_truncated else "",
                stderr_bytes.decode("utf-8", errors="replace").strip(),
            )
            raise RuntimeError(
                f"credential proxy shell bootstrap failed with exit code {result.returncode}"
            )

    def execute(
        self,
        argv: list[str],
        stdin: str | None = None,
        cwd: str | None = None,
        kubeconfig: str | None = None,
    ) -> ExecutionResult:
        if (
            not isinstance(argv, list)
            or not argv
            or not all(isinstance(argument, str) for argument in argv)
        ):
            raise ValueError("argv must be a non-empty list of strings")
        executable = argv[0]
        if executable not in self.ALLOWED_EXECUTABLES:
            raise ValueError("executable is not supported by the credential proxy")
        executable_path = self.executables.get(executable)
        if not executable_path:
            raise RuntimeError(f"supported executable is unavailable: {executable}")
        command = [executable_path, *argv[1:]]

        # `get-credentials` is the one command that legitimately authors a
        # kubeconfig, so it is handled separately: it writes, everything else
        # reads.
        if _is_get_credentials(argv):
            return self._execute_get_credentials(command, stdin, cwd, kubeconfig)

        # Two ways in, and both have to be covered or the other is a bypass.
        # `--kubeconfig` predates the KUBECONFIG forward and takes precedence
        # over it in kubectl, so closing only the environment would leave the
        # flag as an open door.
        command = self._reroute_kubeconfig_flags(command)
        kubeconfig_path = self._resolve_kubeconfig(kubeconfig) if kubeconfig else None
        return self._execute(
            command,
            stdin=stdin,
            cwd=cwd,
            kubeconfig_path=kubeconfig_path,
        )

    def execute_internal(
        self, argv: list[str], cwd: str | None = None
    ) -> ExecutionResult:
        """Run a trusted, operator-defined helper that is not agent selectable."""
        return self._execute(argv, cwd=cwd)

    def _within_workspace(self, candidate: Path) -> bool:
        return candidate == self.workspace_dir or self.workspace_dir in candidate.parents

    def _lease_holder(self, candidate: Path) -> Path | None:
        """The nearest ancestor of `candidate` that holds a lease marker."""
        for directory in (candidate, *candidate.parents):
            if not self._within_workspace(directory):
                break
            try:
                if (directory / GIT_LEASE_MARKER).is_file():
                    return directory
            except OSError:
                break
        return None

    def git_lease_violation(self, argv: list[str], cwd: str | None) -> str | None:
        """Why this git command may not run here, or None if it may.

        The pod runs many agents against one PersistentVolumeClaim. Containment
        to `/opt/data` keeps them off the sidecar's filesystem but says nothing
        about keeping them off *each other*, and the shared clone that used to
        sit at the workspace root was a directory every agent wrote in at once.
        Skills now take a lease and get a private clone under it; this is the
        floor that stops a skill which does not from mutating a tree anyway.

        It is a floor and not an ownership check. The client sends argv and a
        working directory — never a caller identity — so the proxy can tell that
        a push is happening inside *some* lease but not whose. Ownership is
        checked by the skill (`gitops_workspace.assert_lease_owner`), which is
        the only layer that knows which lease it holds.
        """
        if not self.require_git_lease:
            return None
        if not argv or Path(argv[0]).name != "git":
            return None
        subcommand, redirects, _ = _git_plan(argv)
        if subcommand not in GIT_MUTATING_SUBCOMMANDS:
            return None

        candidate = Path(cwd).resolve() if cwd else self.workspace_dir
        # `-C` is applied the way git applies it: each one relative to the last.
        for redirect in redirects:
            candidate = (candidate / redirect).resolve()

        if not self._within_workspace(candidate):
            return (
                f"`git {subcommand}` would run in {candidate}, outside the shared "
                "workspace."
            )
        if self._lease_holder(candidate) is None:
            return (
                f"`git {subcommand}` is only allowed inside a leased GitOps "
                f"workspace, and {candidate} is not one (no {GIT_LEASE_MARKER} in "
                "it or any directory above it). Other agents share this volume: "
                "run the skill's workspace step — `audit_report.py start` for a "
                "fleet audit, `submit_suggestion.py prepare` for a suggestion — "
                "and work in the directory it prints."
            )
        return None

    def _workspace_kubeconfig(self, kubeconfig: str) -> Path:
        """Hold a caller-supplied kubeconfig path to the shared workspace.

        Cluster Agent profiles pin themselves to one cluster through this path,
        but the client cannot simply forward its environment: the command
        executes in the sidecar, where the agent must not be able to reach
        credential material. The path is therefore held to the same containment
        rule as `cwd`. Paths elsewhere in the sidecar filesystem are rejected
        rather than silently ignored, so a mistake surfaces as an error instead
        of a command that quietly talks to the wrong cluster.

        A `path1:path2` merge list is refused outright. kubectl would flatten it
        into one view, and there is no sound way to regenerate a merge of
        documents whose contents are never trusted in the first place.
        """
        entries = [entry.strip() for entry in kubeconfig.split(os.pathsep) if entry.strip()]
        if not entries:
            raise ValueError("kubeconfig must not be empty")
        if len(entries) > 1:
            raise ValueError(
                "kubeconfig must name a single file; merged KUBECONFIG lists are not supported"
            )
        candidate = Path(entries[0]).resolve()
        if not self._within_workspace(candidate):
            raise ValueError("kubeconfig is outside the shared workspace")
        return candidate

    def _resolve_kubeconfig(self, kubeconfig: str) -> Path:
        """Turn a caller's kubeconfig path into one the proxy wrote itself.

        The caller's file is treated as a *name*, not as content. Exactly one
        string is taken from it — `current-context` — and that string is only
        accepted if it is a well-formed GKE context name, which is enough to say
        which cluster is wanted. The kubeconfig the command then runs against is
        regenerated by `gcloud container clusters get-credentials` against the
        live GKE API and kept in a directory the agent cannot write.

        So every field that made a caller-supplied kubeconfig dangerous — the
        `exec` stanza, `auth-provider`, `server`, `proxy-url`, `tokenFile`,
        `insecure-skip-tls-verify` — is now written by gcloud rather than by the
        agent. There is no allowlist to keep current and no document to re-check
        at open time, because nothing the agent authored is ever opened.

        What the caller keeps is the ability to *name* a cluster. That is not new
        authority: `get-credentials` is bound by the same IAM the proxy already
        runs under, so it can only name clusters this identity could reach anyway.
        """
        requested = self._workspace_kubeconfig(kubeconfig)
        return self._ensure_managed_kubeconfig(self._target_of(requested))

    def _reroute_kubeconfig_flags(self, command: list[str]) -> list[str]:
        """Point any `--kubeconfig` in argv at the regenerated file.

        kubectl prefers this flag over the environment, and it reaches the
        sidecar untouched — the policy engine matches on argv but has no rule for
        it, and the workspace PVC is mounted here. Left alone it would be the
        simplest way around everything `_resolve_kubeconfig` does.
        """
        rewritten = list(command)
        index = 1
        while index < len(rewritten):
            argument = rewritten[index]
            if argument == "--kubeconfig" and index + 1 < len(rewritten):
                rewritten[index + 1] = str(self._resolve_kubeconfig(rewritten[index + 1]))
                index += 2
                continue
            if argument.startswith("--kubeconfig="):
                resolved = self._resolve_kubeconfig(argument.split("=", 1)[1])
                rewritten[index] = f"--kubeconfig={resolved}"
            index += 1
        return rewritten

    def _target_of(self, requested: Path) -> ClusterTarget:
        """Read the wanted cluster out of the caller's kubeconfig."""
        try:
            if requested.stat().st_size > MAX_KUBECONFIG_BYTES:
                raise ValueError(f"kubeconfig is implausibly large: {requested}")
            text = requested.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            raise ValueError(f"kubeconfig is unreadable: {requested}") from error
        context = read_current_context(text)
        if not context:
            raise ValueError(f"kubeconfig names no current-context: {requested}")
        target = parse_gke_context(context)
        if target is None:
            raise ValueError(
                f"current-context {context!r} is not a GKE context name"
                " (expected gke_<project>_<location>_<cluster>)"
            )
        return target

    def _managed_kubeconfig(self, target: ClusterTarget) -> Path:
        return self.kubeconfig_dir / f"{target.context_name}.yaml"

    def _ensure_managed_kubeconfig(self, target: ClusterTarget) -> Path:
        """Return the proxy-authored kubeconfig for a cluster, fetching on a miss.

        A miss costs one `get-credentials`. In practice the common paths warm the
        cache themselves: both `cluster_agent_profile.py` and the Platform Agent's
        `switch_kube_context` reach a cluster by running that command first, and
        `_execute_get_credentials` files the result here. This is the cold path —
        a restart, since the state dir is an emptyDir, or a kubeconfig that was
        pinned by some earlier process.
        """
        managed = self._managed_kubeconfig(target)
        with self._kubeconfig_lock:
            if managed.is_file() and managed.stat().st_size > 0:
                return managed
            gcloud = self.executables.get("gcloud")
            if not gcloud:
                raise RuntimeError("gcloud is unavailable; cannot materialise a kubeconfig")
            scratch = self.kubeconfig_dir / f".pending-{uuid.uuid4().hex}.yaml"
            try:
                result = self._execute(
                    [
                        gcloud,
                        "container",
                        "clusters",
                        "get-credentials",
                        target.cluster,
                        f"--location={target.location}",
                        f"--project={target.project}",
                    ],
                    kubeconfig_path=scratch,
                )
                if result.exit_code != 0 or not scratch.is_file():
                    detail = result.stderr.strip() or f"gcloud exited {result.exit_code}"
                    raise ValueError(
                        f"could not obtain credentials for {target.context_name}: {detail[:400]}"
                    )
                os.replace(scratch, managed)
            finally:
                scratch.unlink(missing_ok=True)
        return managed

    def _execute_get_credentials(
        self,
        command: list[str],
        stdin: str | None,
        cwd: str | None,
        kubeconfig: str | None,
    ) -> ExecutionResult:
        """Run the one command that is allowed to author a kubeconfig.

        gcloud writes into the proxy's own directory, never straight to the path
        the caller asked for. The generated file is then filed under the context
        it selects — that read is trustworthy because gcloud, not the agent, just
        wrote it — and copied out to the caller so the workspace still holds the
        visible pin that `cluster_agent_profile.py` records and the Cluster Agent
        preflight stats. That copy is an artefact for the agent to look at; it is
        never what a later command runs against.
        """
        if not kubeconfig:
            # No destination asked for, so gcloud updates the sidecar's own
            # config as it always has. Nothing agent-authored is involved.
            return self._execute(command, stdin=stdin, cwd=cwd)

        requested = self._workspace_kubeconfig(kubeconfig)
        scratch = self.kubeconfig_dir / f".pending-{uuid.uuid4().hex}.yaml"
        try:
            result = self._execute(command, stdin=stdin, cwd=cwd, kubeconfig_path=scratch)
            if result.exit_code == 0 and scratch.is_file():
                generated = scratch.read_text(encoding="utf-8")
                context = read_current_context(generated)
                target = parse_gke_context(context) if context else None
                if target is not None:
                    # Deliberately outside `_kubeconfig_lock`: `os.replace` is
                    # atomic, so a concurrent cache miss for the same cluster
                    # either sees the old file or this one, and at worst does one
                    # redundant fetch. Taking the lock here would serialise every
                    # scaffold behind every cold read for no benefit.
                    os.replace(scratch, self._managed_kubeconfig(target))
                requested.parent.mkdir(parents=True, exist_ok=True)
                requested.write_text(generated, encoding="utf-8")
            return result
        finally:
            scratch.unlink(missing_ok=True)

    def _execute(
        self,
        argv: list[str],
        stdin: str | None = None,
        cwd: str | None = None,
        kubeconfig_path: Path | None = None,
    ) -> ExecutionResult:
        """Run a command. `kubeconfig_path` is already resolved and trusted.

        Callers hand this an absolute path the proxy itself owns; containment and
        regeneration happen in `execute` so that nothing reaching this point is
        still caller-controlled.
        """
        started = time.monotonic()
        timed_out = False
        command_cwd = self.workspace_dir
        if cwd:
            requested_cwd = Path(cwd).resolve()
            if not self._within_workspace(requested_cwd):
                raise ValueError("working directory is outside the shared workspace")
            command_cwd = requested_cwd
        command_environment = self.environment.copy()
        if argv and Path(argv[0]).name == "git":
            command_environment.update(self.git_identity)
        if kubeconfig_path is not None:
            command_environment["KUBECONFIG"] = str(kubeconfig_path)
        process = subprocess.Popen(
            argv,
            cwd=command_cwd,
            env=command_environment,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout_bytes, stderr_bytes = process.communicate(
                input=stdin.encode("utf-8") if stdin is not None else None,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            stdout_bytes, stderr_bytes = process.communicate()

        stdout_bytes, stdout_truncated = self._truncate(stdout_bytes)
        stderr_bytes, stderr_truncated = self._truncate(stderr_bytes)
        duration_ms = int((time.monotonic() - started) * 1000)
        return ExecutionResult(
            exit_code=124 if timed_out else process.returncode,
            stdout=stdout_bytes.decode("utf-8", errors="replace"),
            stderr=stderr_bytes.decode("utf-8", errors="replace"),
            duration_ms=duration_ms,
            truncated=stdout_truncated or stderr_truncated,
            timed_out=timed_out,
        )

    def _truncate(self, value: bytes) -> tuple[bytes, bool]:
        if len(value) <= self.max_output_bytes:
            return value, False
        return value[: self.max_output_bytes], True


class CredentialProxyHandler(BaseHTTPRequestHandler):
    policy: Policy
    executor: CommandExecutor
    max_request_bytes: int
    slack_max_request_bytes: int
    chat_relay: GoogleChatRelay | None = None
    slack_relay: SlackRelay | None = None

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/v1/chat/slack/events"):
            if self.slack_relay is None:
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Slack relay disabled"}
                )
                return
            try:
                self._json(HTTPStatus.OK, {"event": self.slack_relay.pull()})
            except Exception as exc:
                LOGGER.warning("Slack event pull failed: %s", type(exc).__name__)
                self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Slack event pull failed"}
                )
            return
        if self.path.startswith("/v1/chat/events"):
            if self.chat_relay is None:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "chat relay disabled"})
                return
            try:
                event = self.chat_relay.pull()
                self._json(HTTPStatus.OK, {"event": event})
            except Exception as exc:
                LOGGER.warning("chat event pull failed: %s", type(exc).__name__)
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "chat event pull failed"})
            return
        if self.path != "/healthz":
            self._json(HTTPStatus.NOT_FOUND, {"status": "not_found"})
            return
        self._json(HTTPStatus.OK, {"status": "ok"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.startswith("/v1/chat/slack/"):
            self._handle_slack_post()
            return
        if self.path.startswith("/v1/chat/"):
            self._handle_chat_post()
            return
        if self.path == "/v1/github/refresh":
            self._handle_github_refresh()
            return
        if self.path != "/v1/exec":
            self._json(HTTPStatus.NOT_FOUND, {"status": "not_found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid content length"})
            return
        if content_length <= 0 or content_length > self.max_request_bytes:
            self._json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "command request exceeds configured size limit"},
            )
            return

        try:
            payload = json.loads(self.rfile.read(content_length))
            argv = payload["argv"]
            if (
                not isinstance(argv, list)
                or not argv
                or not all(isinstance(argument, str) for argument in argv)
            ):
                raise ValueError("argv must be a non-empty list of strings")
            stdin = payload.get("stdin")
            if stdin is not None and not isinstance(stdin, str):
                raise ValueError("stdin must be a string")
            cwd = payload.get("cwd")
            if cwd is not None and not isinstance(cwd, str):
                raise ValueError("cwd must be a string")
            kubeconfig = payload.get("kubeconfig")
            if kubeconfig is not None and not isinstance(kubeconfig, str):
                raise ValueError("kubeconfig must be a string")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        request_id = str(payload.get("requestId", ""))
        if argv[0] not in CommandExecutor.ALLOWED_EXECUTABLES:
            LOGGER.warning(
                "executable blocked request_id=%s executable=%s",
                request_id,
                argv[0],
            )
            self._json(
                HTTPStatus.FORBIDDEN,
                {
                    "status": "blocked",
                    "code": "SECURITY_POLICY_BLOCKED",
                    "rule": "executable.allowlist",
                    "message": "Executable is not supported by the credential proxy.",
                },
            )
            return
        rule = self.policy.blocked_by(argv)
        if rule is not None:
            LOGGER.warning(
                "command blocked request_id=%s rule=%s", request_id, rule.rule_id
            )
            self._json(
                HTTPStatus.FORBIDDEN,
                {
                    "status": "blocked",
                    "code": "SECURITY_POLICY_BLOCKED",
                    "rule": rule.rule_id,
                    "message": rule.message,
                },
            )
            return

        # Not a policy rule either: the rules match a regex against the joined
        # command string, and every question this gate asks — which token is the
        # verb, which is the resource, is that flag's value or the next argument
        # — is a question about argv's structure that a regex over the join can
        # only approximate.
        kubectl_violation = self.policy.kubernetes.violation(argv)
        if kubectl_violation is not None:
            if self.policy.kubernetes.enforcing:
                LOGGER.warning(
                    "kubectl refused request_id=%s reason=%s",
                    request_id,
                    kubectl_violation,
                )
                self._json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "status": "blocked",
                        "code": "SECURITY_POLICY_BLOCKED",
                        "rule": KubernetesPolicy.RULE_ID,
                        "message": kubectl_violation,
                    },
                )
                return
            # Warn mode. Logged at warning so it shows up in the same sidecar
            # log a real refusal would, and named `would_refuse` so nobody reads
            # a survey of the fleet's kubectl usage as a list of blocked
            # commands. This line is the evidence for flipping to enforce.
            LOGGER.warning(
                "kubectl would_refuse request_id=%s reason=%s",
                request_id,
                kubectl_violation,
            )

        # Runs before the lease check, so that `git push origin main` inside a
        # perfectly valid lease is refused for landing on `main` rather than
        # passing, and so that a `gh` refusal does not depend on a lease `gh`
        # never needed.
        forge_violation = self.policy.forge.violation(argv)
        if forge_violation is not None:
            if self.policy.forge.enforcing:
                LOGGER.warning(
                    "forge refused request_id=%s rule=%s reason=%s",
                    request_id,
                    forge_violation.rule_id,
                    forge_violation.message,
                )
                self._json(
                    HTTPStatus.FORBIDDEN,
                    {
                        "status": "blocked",
                        "code": "SECURITY_POLICY_BLOCKED",
                        "rule": forge_violation.rule_id,
                        "message": forge_violation.message,
                    },
                )
                return
            LOGGER.warning(
                "forge would_refuse request_id=%s rule=%s reason=%s",
                request_id,
                forge_violation.rule_id,
                forge_violation.message,
            )

        # Not a policy rule: the policy matches on argv alone, and this refusal
        # turns on the working directory as well.
        violation = self.executor.git_lease_violation(argv, cwd)
        if violation is not None:
            LOGGER.warning(
                "git lease refused request_id=%s cwd=%s", request_id, cwd
            )
            self._json(
                HTTPStatus.FORBIDDEN,
                {
                    "status": "blocked",
                    "code": "SECURITY_POLICY_BLOCKED",
                    "rule": "git.workspace.lease",
                    "message": violation,
                },
            )
            return

        try:
            result = self.executor.execute(
                argv, stdin=stdin, cwd=cwd, kubeconfig=kubeconfig
            )
        except ValueError as exc:
            # Containment rejections (cwd or kubeconfig outside the workspace)
            # are caller errors, not proxy faults. Returning the reason keeps
            # them from reading as an unexplained proxy outage — the agent can
            # correct the path instead of guessing.
            LOGGER.warning(
                "command rejected request_id=%s reason=%s", request_id, exc
            )
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        except Exception as exc:
            LOGGER.exception(
                "command failed request_id=%s type=%s",
                request_id,
                type(exc).__name__,
            )
            self._json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "credential proxy command execution failed"},
            )
            return
        LOGGER.info(
            "command complete request_id=%s exit_code=%d duration_ms=%d truncated=%s",
            request_id,
            result.exit_code,
            result.duration_ms,
            result.truncated,
        )
        self._json(
            HTTPStatus.OK,
            {
                "status": "completed",
                "exitCode": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "durationMs": result.duration_ms,
                "truncated": result.truncated,
                "timedOut": result.timed_out,
            },
        )

    def _handle_github_refresh(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > self.max_request_bytes:
                raise ValueError("invalid request size")
            payload = json.loads(self.rfile.read(content_length))
            repository = payload["repository"]
            if not is_valid_repository(repository):
                raise ValueError("repository must be owner/name")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        try:
            result = self.executor.execute_internal(
                ["/opt/defaults/scripts/github_token_refresh.py", repository]
            )
        except Exception as exc:
            LOGGER.warning("GitHub credential refresh failed: %s", type(exc).__name__)
            self._json(
                HTTPStatus.BAD_GATEWAY, {"error": "GitHub credential refresh failed"}
            )
            return
        if result.exit_code != 0:
            LOGGER.warning("GitHub credential refresh exited %d", result.exit_code)
            self._json(
                HTTPStatus.BAD_GATEWAY, {"error": "GitHub credential refresh failed"}
            )
            return
        self._json(HTTPStatus.OK, {"status": "refreshed"})

    def _read_json_body(self, max_bytes: int | None = None) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0 or content_length > (
            max_bytes or self.max_request_bytes
        ):
            raise ValueError("request exceeds configured size limit")
        payload = json.loads(self.rfile.read(content_length))
        if not isinstance(payload, dict):
            raise ValueError("request body must be an object")
        return payload

    def _handle_chat_post(self) -> None:
        if self.chat_relay is None:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "chat relay disabled"})
            return
        try:
            payload = self._read_json_body()
            if self.path == "/v1/chat/events/ack":
                ok = self.chat_relay.settle(str(payload.get("receipt", "")), True)
                self._json(HTTPStatus.OK if ok else HTTPStatus.NOT_FOUND, {"settled": ok})
                return
            if self.path == "/v1/chat/events/nack":
                ok = self.chat_relay.settle(str(payload.get("receipt", "")), False)
                self._json(HTTPStatus.OK if ok else HTTPStatus.NOT_FOUND, {"settled": ok})
                return
            if self.path == "/v1/chat/api":
                resource = payload.get("resource", [])
                arguments = payload.get("arguments", {})
                if not isinstance(resource, list) or not isinstance(arguments, dict):
                    raise ValueError("resource must be a list and arguments an object")
                result = self.chat_relay.api_call(
                    resource,
                    str(payload.get("method", "")),
                    arguments,
                )
                self._json(HTTPStatus.OK, {"response": result})
                return
            self._json(HTTPStatus.NOT_FOUND, {"status": "not_found"})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            # Carry the status line of a Google Chat rejection back to the
            # agent and into this log. Without it a transport fault, a 404 for
            # an unknown space and a 403 for a missing scope are one
            # indistinguishable "operation failed", and the retries inside
            # api_call have already absorbed everything genuinely transient —
            # so what reaches here is usually worth naming.
            fields = _chat_error_fields(exc)
            LOGGER.warning(
                "chat relay operation failed path=%s type=%s status=%s",
                self.path,
                type(exc).__name__,
                (fields or {}).get("status", "none"),
            )
            body: dict[str, Any] = {"error": "Google Chat operation failed"}
            if fields:
                body["chat"] = fields
            self._json(HTTPStatus.BAD_GATEWAY, body)

    def _handle_slack_post(self) -> None:
        if self.slack_relay is None:
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Slack relay disabled"}
            )
            return
        try:
            payload = self._read_json_body(self.slack_max_request_bytes)
            if self.path == "/v1/chat/slack/bootstrap":
                self._json(
                    HTTPStatus.OK,
                    {"workspaces": self.slack_relay.bootstrap()},
                )
                return
            if self.path == "/v1/chat/slack/events/ack":
                ok = self.slack_relay.settle(str(payload.get("receipt", "")), True)
                self._json(
                    HTTPStatus.OK if ok else HTTPStatus.NOT_FOUND, {"settled": ok}
                )
                return
            if self.path == "/v1/chat/slack/events/nack":
                ok = self.slack_relay.settle(str(payload.get("receipt", "")), False)
                self._json(
                    HTTPStatus.OK if ok else HTTPStatus.NOT_FOUND, {"settled": ok}
                )
                return
            if self.path == "/v1/chat/slack/api":
                arguments = payload.get("arguments", {})
                if not isinstance(arguments, dict):
                    raise ValueError("arguments must be an object")
                result = self.slack_relay.api_call(
                    str(payload.get("teamId", "")),
                    str(payload.get("method", "")),
                    arguments,
                )
                self._json(HTTPStatus.OK, {"response": result})
                return
            if self.path == "/v1/chat/slack/files/download":
                content = self.slack_relay.download(
                    str(payload.get("teamId", "")), str(payload["url"])
                )
                self._json(
                    HTTPStatus.OK,
                    {"data": base64.b64encode(content).decode("ascii")},
                )
                return
            self._json(HTTPStatus.NOT_FOUND, {"status": "not_found"})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception as exc:
            LOGGER.warning(
                "Slack relay operation failed path=%s type=%s error=%s",
                self.path,
                type(exc).__name__,
                _slack_error_detail(exc),
            )
            # Carry the whitelisted diagnostic fields back to the agent, not
            # just to this log. slack_sdk raises SlackApiError for an
            # ``ok: false``, so without this the specific cause —
            # channel_not_found, not_in_channel, missing_scope — dies here and
            # the caller sees an indistinguishable "Slack operation failed"
            # for every one of them. slack_relay_patch turns the ``slack`` key
            # back into the SlackApiError the real client would have raised.
            body: dict[str, Any] = {"error": "Slack operation failed"}
            fields = _slack_error_fields(exc)
            if fields:
                body["slack"] = fields
            self._json(HTTPStatus.BAD_GATEWAY, body)

    def log_message(self, message: str, *args: Any) -> None:
        LOGGER.info("http " + message, *args)

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(args: argparse.Namespace) -> None:
    CredentialProxyHandler.policy = Policy.load(args.policy)
    # Stated at startup because the alternative is inferring it from the absence
    # of refusals, and "nothing was refused" reads identically whether the gate
    # is enforcing against well-behaved skills or is switched off entirely.
    kubernetes_policy = CredentialProxyHandler.policy.kubernetes
    LOGGER.info(
        "kubectl read-only gate mode=%s namespaces=%s",
        kubernetes_policy.mode,
        ",".join(kubernetes_policy.allowed_namespaces) or "<unrestricted>",
    )
    forge_policy = CredentialProxyHandler.policy.forge
    LOGGER.info(
        "forge branch-and-pr gate mode=%s protected=%s",
        forge_policy.mode,
        ",".join(forge_policy.protected_branches) or "<none>",
    )
    executor = CommandExecutor(
        timeout_seconds=args.timeout_seconds,
        max_output_bytes=args.max_output_bytes,
        state_dir=args.state_dir,
    )
    executor.bootstrap(os.getenv("CREDENTIAL_PROXY_BOOTSTRAP_COMMAND", ""))
    CredentialProxyHandler.executor = executor
    CredentialProxyHandler.max_request_bytes = args.max_request_bytes
    CredentialProxyHandler.slack_max_request_bytes = int(
        os.getenv("SLACK_RELAY_MAX_REQUEST_BYTES", str(28 * 1024 * 1024))
    )
    chat_project = os.getenv("GOOGLE_CHAT_PROJECT_ID", "").strip()
    chat_subscription = os.getenv("GOOGLE_CHAT_SUBSCRIPTION_NAME", "").strip()
    if chat_project and chat_subscription:
        CredentialProxyHandler.chat_relay = GoogleChatRelay(
            chat_project, chat_subscription
        )
        LOGGER.info("Google Chat relay enabled project=%s subscription=<redacted>", chat_project)
    slack_bot_tokens = os.getenv("SLACK_BOT_TOKEN", "").strip()
    slack_app_token = os.getenv("SLACK_APP_TOKEN", "").strip()
    if slack_bot_tokens and slack_app_token:
        def initialize_slack_relay() -> None:
            while CredentialProxyHandler.slack_relay is None:
                try:
                    relay = SlackRelay(
                        slack_bot_tokens,
                        slack_app_token,
                        max_file_bytes=int(
                            os.getenv(
                                "SLACK_RELAY_MAX_FILE_BYTES", str(20 * 1024 * 1024)
                            )
                        ),
                    )
                except Exception as exc:
                    LOGGER.error(
                        "Slack relay initialization failed; retrying type=%s",
                        type(exc).__name__,
                    )
                    time.sleep(30)
                else:
                    CredentialProxyHandler.slack_relay = relay
                    LOGGER.info(
                        "Slack relay enabled workspaces=%d",
                        len(relay.bootstrap()),
                    )

        threading.Thread(target=initialize_slack_relay, daemon=True).start()
    AgentAPIProxyHandler.external_key = os.getenv("API_SERVER_EXTERNAL_KEY", "").strip()
    if not AgentAPIProxyHandler.external_key:
        raise RuntimeError("API_SERVER_EXTERNAL_KEY must be configured")
    AgentAPIProxyHandler.upstream_key = os.getenv(
        "AGENT_API_UPSTREAM_KEY", "cluster-internal-trusted"
    )
    api_server = ThreadingHTTPServer(
        ("0.0.0.0", int(os.getenv("AGENT_API_PROXY_PORT", "8643"))),
        AgentAPIProxyHandler,
    )
    threading.Thread(target=api_server.serve_forever, daemon=True).start()
    LOGGER.info("authenticated PlatformAgent API proxy listening on port 8643")
    if args.unix_socket:
        socket_path = Path(args.unix_socket)
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        socket_path.unlink(missing_ok=True)
        server = ThreadingUnixHTTPServer(str(socket_path), CredentialProxyHandler)
        LOGGER.info("credential proxy listening on unix socket %s", socket_path)
    else:
        server = ThreadingHTTPServer((args.host, args.port), CredentialProxyHandler)
        LOGGER.info("credential proxy listening on %s:%d", args.host, args.port)
    server.serve_forever()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=os.getenv(
            "CREDENTIAL_PROXY_POLICY", "/etc/credential-proxy/policy.json"
        ),
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument(
        "--port", type=int, default=int(os.getenv("CREDENTIAL_PROXY_PORT", "8765"))
    )
    parser.add_argument(
        "--unix-socket", default=os.getenv("CREDENTIAL_PROXY_UNIX_SOCKET", "")
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=int(os.getenv("CREDENTIAL_PROXY_TIMEOUT_SECONDS", "300")),
    )
    parser.add_argument(
        "--max-request-bytes",
        type=int,
        default=int(os.getenv("CREDENTIAL_PROXY_MAX_REQUEST_BYTES", "1048576")),
    )
    parser.add_argument(
        "--max-output-bytes",
        type=int,
        default=int(os.getenv("CREDENTIAL_PROXY_MAX_OUTPUT_BYTES", "4194304")),
    )
    parser.add_argument(
        "--state-dir",
        default=os.getenv("CREDENTIAL_PROXY_STATE_DIR", "/var/lib/credential-proxy"),
    )
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    serve(parse_args())
