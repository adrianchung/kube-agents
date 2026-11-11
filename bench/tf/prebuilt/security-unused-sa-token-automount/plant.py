# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Plant and remove the GitOps declarations for security-unused-sa-token-automount-pr.

main.tf invokes `python3 plant.py plant` on apply and `python3 plant.py teardown`
on destroy with settings passed through environment variables (`Settings.from_env`).

The stack plants four workload manifests under
`clusters/<host_cluster_name>/namespaces/<namespace>/`:
  - `order-processor.yaml`: named ServiceAccount with zero RoleBindings, zero
    ClusterRoleBindings, zero Workload Identity IAM annotations, and no
    container volumeMount at `/var/run/secrets/kubernetes.io/serviceaccount`
    (the single workload safe for `automountServiceAccountToken: false`).
  - `config-watcher.yaml`: ServiceAccount bound by a RoleBinding (`Role` reading
    ConfigMaps) -- must NOT have token auto-mounting disabled.
  - `gcs-archiver.yaml`: ServiceAccount carrying an `iam.gke.io/gcp-service-account`
    Workload Identity annotation -- must NOT have token auto-mounting disabled.
  - `vault-fetcher.yaml`: container explicitly mounting a projected token volume
    at `/var/run/secrets/kubernetes.io/serviceaccount` -- must NOT be modified.

Every planted manifest carries `metadata.labels.managed-by: kube-agents-bench`
so `plant` refuses to clobber foreign files and `teardown` deletes only files
owned by this stack. When `SA_AUTOMOUNT_EVAL_GITOPS_BASE_BRANCH` names a
non-default branch (for local dev runs against a live Argo CD repository),
`plant` creates or resets that branch from the repository's default branch and
`teardown` closes open pull requests targeting it and deletes the branch,
leaving the default branch untouched.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, NamedTuple

MANAGED_BY_KEY = "managed-by"
MANAGED_BY = "kube-agents-bench"
CASE = "security-unused-sa-token-automount-pr"
AUDIT_REMEDIATION_LABEL = "audit:remediation"
STALE_CLOSED_LABEL = "audit:stale-closed"
GITHUB_API = "https://api.github.com"
HTTP_TIMEOUT_S = 30
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204
HTTP_NOT_FOUND = 404
HTTP_UNPROCESSABLE = 422
PUT_OK_STATUSES = (HTTP_OK, HTTP_CREATED)
LABEL_OK_STATUSES = (HTTP_OK, HTTP_CREATED)
RETRY_DELAYS_S = (2, 8)
RETRYABLE_STATUS_FLOOR = 500
NO_ANSWER = 0
GITHUB_PAGE = 100
MAX_PAGES = 10
USAGE = "usage: plant.py plant|teardown"
WI_GSA = "gcs-archiver@kube-agents-bench-no-such-fixture-project.iam.gserviceaccount.com"
DEFAULT_NAMESPACE = "seeded-sa-automount"
BOT_LOGIN_SUFFIX = "[bot]"
EVAL_BRANCH_PREFIX = "eval-"

HttpFn = Callable[[str, str, "dict | None"], "tuple[int, object]"]


class Settings(NamedTuple):
    gitops_repo: str
    cluster_name: str
    namespace: str
    token_file: str
    base_branch: str = ""

    @property
    def directory(self) -> str:
        return f"clusters/{self.cluster_name}/namespaces/{self.namespace}"

    def github_token(self) -> str:
        """Read per request so renewed runner tokens are picked up automatically."""
        return Path(self.token_file).read_text(encoding="utf-8").strip()

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            gitops_repo=os.environ.get("SA_AUTOMOUNT_EVAL_GITOPS_REPO", "").strip(),
            cluster_name=os.environ.get("SA_AUTOMOUNT_EVAL_CLUSTER_NAME", "").strip(),
            namespace=os.environ.get(
                "SA_AUTOMOUNT_EVAL_NAMESPACE", DEFAULT_NAMESPACE
            ).strip(),
            token_file=os.environ.get("SA_AUTOMOUNT_EVAL_GITOPS_TOKEN_FILE", "").strip(),
            base_branch=os.environ.get(
                "SA_AUTOMOUNT_EVAL_GITOPS_BASE_BRANCH", ""
            ).strip(),
        )


def log(message: str) -> None:
    print(f"[security-unused-sa-token-automount] {message}", file=sys.stderr, flush=True)


def github_http(
    token: Callable[[], str], sleep: Callable[[float], None] = time.sleep
) -> HttpFn:
    """Execute a GitHub REST API request with retry on 5xx / network errors."""

    def once(method: str, path: str, body: dict | None) -> tuple[int, object]:
        request = urllib.request.Request(
            GITHUB_API + path,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            method=method,
            headers={
                "Authorization": f"Bearer {token()}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_S) as response:
                text = response.read().decode("utf-8")
                return response.status, json.loads(text) if text else None
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except OSError:
            return NO_ANSWER, None

    def call(method: str, path: str, body: dict | None) -> tuple[int, object]:
        for delay in (*RETRY_DELAYS_S, None):
            status, parsed = once(method, path, body)
            if delay is None or (status != NO_ANSWER and status < RETRYABLE_STATUS_FLOOR):
                return status, parsed
            log(f"{method} {path} returned {status or 'no response'}; retrying in {delay}s")
            sleep(delay)
        raise AssertionError("unreachable")

    return call


def render_manifests(namespace: str) -> dict[str, str]:
    """Return filename -> YAML text for the four pre-flight test workloads."""
    common_security = """      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        seccompProfile:
          type: RuntimeDefault"""
    common_container = """          image: registry.k8s.io/pause:3.10
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: 10m
              memory: 16Mi
            limits:
              memory: 32Mi"""

    order_processor = f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: order-processor-sa
  namespace: {namespace}
  labels:
    app: order-processor
    {MANAGED_BY_KEY}: {MANAGED_BY}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: order-processor
  namespace: {namespace}
  labels:
    app: order-processor
    {MANAGED_BY_KEY}: {MANAGED_BY}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: order-processor
  template:
    metadata:
      labels:
        app: order-processor
    spec:
      serviceAccountName: order-processor-sa
{common_security}
      containers:
        - name: app
{common_container}
"""

    config_watcher = f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: config-watcher-sa
  namespace: {namespace}
  labels:
    app: config-watcher
    {MANAGED_BY_KEY}: {MANAGED_BY}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: config-watcher-role
  namespace: {namespace}
  labels:
    app: config-watcher
    {MANAGED_BY_KEY}: {MANAGED_BY}
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: config-watcher-binding
  namespace: {namespace}
  labels:
    app: config-watcher
    {MANAGED_BY_KEY}: {MANAGED_BY}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: config-watcher-role
subjects:
  - kind: ServiceAccount
    name: config-watcher-sa
    namespace: {namespace}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: config-watcher
  namespace: {namespace}
  labels:
    app: config-watcher
    {MANAGED_BY_KEY}: {MANAGED_BY}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: config-watcher
  template:
    metadata:
      labels:
        app: config-watcher
    spec:
      serviceAccountName: config-watcher-sa
{common_security}
      containers:
        - name: watcher
{common_container}
"""

    gcs_archiver = f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: gcs-archiver-sa
  namespace: {namespace}
  labels:
    app: gcs-archiver
    {MANAGED_BY_KEY}: {MANAGED_BY}
  annotations:
    iam.gke.io/gcp-service-account: {WI_GSA}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gcs-archiver
  namespace: {namespace}
  labels:
    app: gcs-archiver
    {MANAGED_BY_KEY}: {MANAGED_BY}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gcs-archiver
  template:
    metadata:
      labels:
        app: gcs-archiver
    spec:
      serviceAccountName: gcs-archiver-sa
{common_security}
      containers:
        - name: archiver
{common_container}
"""

    vault_fetcher = f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-fetcher-sa
  namespace: {namespace}
  labels:
    app: vault-fetcher
    {MANAGED_BY_KEY}: {MANAGED_BY}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-fetcher
  namespace: {namespace}
  labels:
    app: vault-fetcher
    {MANAGED_BY_KEY}: {MANAGED_BY}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vault-fetcher
  template:
    metadata:
      labels:
        app: vault-fetcher
    spec:
      serviceAccountName: vault-fetcher-sa
{common_security}
      containers:
        - name: fetcher
{common_container}
          volumeMounts:
            - name: custom-sa-token
              mountPath: /var/run/secrets/kubernetes.io/serviceaccount
              readOnly: true
      volumes:
        - name: custom-sa-token
          projected:
            sources:
              - serviceAccountToken:
                  path: token
                  expirationSeconds: 3600
"""

    return {
        "order-processor.yaml": order_processor,
        "config-watcher.yaml": config_watcher,
        "gcs-archiver.yaml": gcs_archiver,
        "vault-fetcher.yaml": vault_fetcher,
    }


def is_owned_manifest(text: str) -> bool:
    expected = f"{MANAGED_BY_KEY}: {MANAGED_BY}"
    return any(line.strip() == expected for line in text.splitlines())


class Planter:
    def __init__(self, settings: Settings, http: HttpFn) -> None:
        self.settings = settings
        self.http = http

    def validate_settings(self) -> None:
        for name, val in (
            ("gitops_repo", self.settings.gitops_repo),
            ("host_cluster_name", self.settings.cluster_name),
            ("namespace", self.settings.namespace),
            ("bench_gitops_write_token_file", self.settings.token_file),
        ):
            if not val:
                raise RuntimeError(f"missing required setting {name}")
        if "/" not in self.settings.gitops_repo:
            raise RuntimeError(
                f"gitops_repo {self.settings.gitops_repo!r} must be owner/name"
            )
        if self.settings.base_branch and not self.settings.base_branch.startswith(
            EVAL_BRANCH_PREFIX
        ):
            raise RuntimeError(
                f"gitops_base_branch {self.settings.base_branch!r} must start with {EVAL_BRANCH_PREFIX!r}"
            )
        if not Path(self.settings.token_file).is_file():
            raise RuntimeError(
                f"bench_gitops_write_token_file {self.settings.token_file!r} does not exist"
            )

    def default_branch(self) -> str:
        status, repo = self.http("GET", f"/repos/{self.settings.gitops_repo}", None)
        if status != HTTP_OK or not isinstance(repo, dict) or not repo.get("default_branch"):
            raise RuntimeError(
                f"GET /repos/{self.settings.gitops_repo} returned {status}; cannot resolve default_branch"
            )
        return str(repo["default_branch"])

    def ensure_branch(self, branch: str, default_branch: str) -> bool:
        if branch == default_branch:
            return False
        base_ref = f"/repos/{self.settings.gitops_repo}/git/ref/heads/{urllib.parse.quote(default_branch, safe='/')}"
        b_status, base_obj = self.http("GET", base_ref, None)
        sha = (
            ((base_obj.get("object") or {}).get("sha") or "")
            if b_status == HTTP_OK and isinstance(base_obj, dict)
            else ""
        )
        if not sha:
            raise RuntimeError(
                f"GET {base_ref} returned {b_status}; cannot cut branch {branch}"
            )
        quoted_branch = urllib.parse.quote(branch, safe="/")
        ref_path = f"/repos/{self.settings.gitops_repo}/git/ref/heads/{quoted_branch}"
        status, existing = self.http("GET", ref_path, None)
        if status == HTTP_OK and isinstance(existing, dict):
            u_status, _ = self.http(
                "PATCH",
                f"/repos/{self.settings.gitops_repo}/git/refs/heads/{quoted_branch}",
                {"sha": sha, "force": True},
            )
            if u_status != HTTP_OK:
                raise RuntimeError(f"resetting branch {branch} returned {u_status}")
            return True
        if status != HTTP_NOT_FOUND:
            raise RuntimeError(f"GET {ref_path} returned {status}")
        c_status, _ = self.http(
            "POST",
            f"/repos/{self.settings.gitops_repo}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": sha},
        )
        if c_status != HTTP_CREATED:
            raise RuntimeError(f"creating branch {branch} returned {c_status}")
        return True

    def get_file(self, rel_path: str, branch: str) -> tuple[str | None, str | None]:
        quoted = urllib.parse.quote(rel_path, safe="/")
        b_quoted = urllib.parse.quote(branch, safe="")
        status, payload = self.http(
            "GET",
            f"/repos/{self.settings.gitops_repo}/contents/{quoted}?ref={b_quoted}",
            None,
        )
        if status == HTTP_NOT_FOUND:
            return None, None
        if status != HTTP_OK or not isinstance(payload, dict):
            raise RuntimeError(f"GET contents/{rel_path}?ref={branch} returned {status}")
        raw_b64 = str(payload.get("content") or "")
        decoded = base64.b64decode(raw_b64).decode("utf-8") if raw_b64 else ""
        return str(payload.get("sha") or ""), decoded

    def put_file(self, rel_path: str, content: str, branch: str, sha: str | None) -> None:
        quoted = urllib.parse.quote(rel_path, safe="/")
        body: dict[str, object] = {
            "message": f"test(bench): plant {Path(rel_path).name} for {CASE}",
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        if sha:
            body["sha"] = sha
        status, _ = self.http(
            "PUT", f"/repos/{self.settings.gitops_repo}/contents/{quoted}", body
        )
        if status not in PUT_OK_STATUSES:
            raise RuntimeError(f"PUT contents/{rel_path} on {branch} returned {status}")

    def delete_file(self, rel_path: str, branch: str, sha: str) -> None:
        quoted = urllib.parse.quote(rel_path, safe="/")
        status, _ = self.http(
            "DELETE",
            f"/repos/{self.settings.gitops_repo}/contents/{quoted}",
            {
                "message": f"test(bench): remove {Path(rel_path).name} for {CASE}",
                "sha": sha,
                "branch": branch,
            },
        )
        if status not in (HTTP_OK, HTTP_NOT_FOUND):
            raise RuntimeError(f"DELETE contents/{rel_path} on {branch} returned {status}")

    def plant(self) -> None:
        self.validate_settings()
        default = self.default_branch()
        target_branch = self.settings.base_branch or default
        manifests = render_manifests(self.settings.namespace)
        created_branch = False
        planted_any = False
        try:
            created_branch = self.ensure_branch(target_branch, default)
            for filename, text in manifests.items():
                rel_path = f"{self.settings.directory}/{filename}"
                sha, existing = self.get_file(rel_path, target_branch)
                if existing is not None and not is_owned_manifest(existing):
                    raise RuntimeError(
                        f"refusing to overwrite unowned file {rel_path} on {target_branch}"
                    )
                self.put_file(rel_path, text, target_branch, sha)
                planted_any = True
                log(f"planted {rel_path} on {target_branch}")
        except Exception:
            if planted_any or created_branch:
                log("plant failed after mutating GitOps state; running teardown")
                self.teardown()
            raise

    def _head_in_repo(self, pr: dict) -> bool:
        head_repo = ((pr.get("head") or {}).get("repo")) or {}
        return (
            isinstance(head_repo, dict)
            and str(head_repo.get("full_name") or "") == self.settings.gitops_repo
        )

    def _pr_touches_directory(self, number: int) -> bool:
        prefix = self.settings.directory + "/"
        for page in range(1, MAX_PAGES + 1):
            status, files = self.http(
                "GET",
                f"/repos/{self.settings.gitops_repo}/pulls/{number}/files?per_page={GITHUB_PAGE}&page={page}",
                None,
            )
            if status != HTTP_OK or not isinstance(files, list):
                raise RuntimeError(
                    f"GET pulls/{number}/files?page={page} returned {status}"
                )
            for entry in files:
                if isinstance(entry, dict) and str(entry.get("filename") or "").startswith(prefix):
                    return True
            if len(files) < GITHUB_PAGE:
                break
        return False

    def _close_matching_pulls(
        self, target_branch: str, default_branch: str, isolated_branch: bool
    ) -> list[str]:
        head_branches: list[str] = []
        b_quoted = urllib.parse.quote(target_branch, safe="")
        for page in range(1, MAX_PAGES + 1):
            status, pulls = self.http(
                "GET",
                f"/repos/{self.settings.gitops_repo}/pulls?state=open&base={b_quoted}&per_page={GITHUB_PAGE}&page={page}",
                None,
            )
            if status != HTTP_OK or not isinstance(pulls, list):
                raise RuntimeError(
                    f"GET pulls?state=open&base={target_branch}&page={page} returned {status}"
                )
            for pr in pulls:
                if not isinstance(pr, dict) or not pr.get("number"):
                    continue
                num = int(pr["number"])
                login = str(((pr.get("user") or {}).get("login")) or "")
                is_bot = login.endswith(BOT_LOGIN_SUFFIX)
                if not (is_bot and self._head_in_repo(pr)):
                    continue
                if not isolated_branch and not self._pr_touches_directory(num):
                    continue
                labels = {
                    str(lbl.get("name") or "")
                    for lbl in (pr.get("labels") or [])
                    if isinstance(lbl, dict)
                }
                if AUDIT_REMEDIATION_LABEL in labels and STALE_CLOSED_LABEL not in labels:
                    l_status, _ = self.http(
                        "POST",
                        f"/repos/{self.settings.gitops_repo}/issues/{num}/labels",
                        {"labels": [STALE_CLOSED_LABEL]},
                    )
                    if l_status not in LABEL_OK_STATUSES:
                        raise RuntimeError(
                            f"adding {STALE_CLOSED_LABEL} to PR #{num} returned {l_status}"
                        )
                c_status, _ = self.http(
                    "PATCH",
                    f"/repos/{self.settings.gitops_repo}/pulls/{num}",
                    {"state": "closed"},
                )
                if c_status != HTTP_OK:
                    raise RuntimeError(f"closing PR #{num} returned {c_status}")
                head_ref = str(((pr.get("head") or {}).get("ref")) or "")
                if head_ref and head_ref not in (default_branch, target_branch):
                    head_branches.append(head_ref)
                log(f"closed PR #{num}")
            if len(pulls) < GITHUB_PAGE:
                break
        return head_branches

    def _delete_branch(self, branch: str) -> None:
        ref_path = f"/repos/{self.settings.gitops_repo}/git/refs/heads/{urllib.parse.quote(branch, safe='/')}"
        status, _ = self.http("DELETE", ref_path, None)
        if status not in (HTTP_NO_CONTENT, HTTP_NOT_FOUND, HTTP_UNPROCESSABLE):
            raise RuntimeError(f"deleting branch {branch} returned {status}")
        log(f"deleted branch {branch} (status {status})")

    def teardown(self) -> None:
        self.validate_settings()
        default = self.default_branch()
        target_branch = self.settings.base_branch or default
        isolated_branch = target_branch != default
        first_error: Exception | None = None
        try:
            head_branches = self._close_matching_pulls(
                target_branch, default, isolated_branch
            )
            for hb in dict.fromkeys(head_branches):
                self._delete_branch(hb)
            if isolated_branch:
                self._delete_branch(target_branch)
        except Exception as exc:
            first_error = exc
        finally:
            if not isolated_branch:
                for filename in render_manifests(self.settings.namespace):
                    rel_path = f"{self.settings.directory}/{filename}"
                    sha, existing = self.get_file(rel_path, target_branch)
                    if sha and existing is not None and is_owned_manifest(existing):
                        self.delete_file(rel_path, target_branch, sha)
                        log(f"removed {rel_path} from {target_branch}")
        if first_error is not None:
            raise first_error


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("plant", "teardown"):
        print(USAGE, file=sys.stderr)
        return 2
    settings = Settings.from_env()
    planter = Planter(settings, github_http(settings.github_token))
    if argv[1] == "plant":
        planter.plant()
    else:
        planter.teardown()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
