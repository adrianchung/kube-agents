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

"""Unit tests for the security-unused-sa-token-automount stack and task.yaml."""

from __future__ import annotations

import base64
import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
STACK = REPO / "bench" / "tf" / "prebuilt" / "security-unused-sa-token-automount"
TASK = REPO / "bench" / "tasks" / "security-unused-sa-token-automount-pr" / "task.yaml"
GITOPS = "gke-agentic/kube-agents-evals-2-infra"
CLUSTER = "platform-agent-host"
NAMESPACE = "seeded-sa-automount"
DIRECTORY = f"clusters/{CLUSTER}/namespaces/{NAMESPACE}"
BOT = "kube-agents-evals[bot]"

_spec = importlib.util.spec_from_file_location("sa_automount_plant", STACK / "plant.py")
plant = importlib.util.module_from_spec(_spec)
sys.modules["sa_automount_plant"] = plant
_spec.loader.exec_module(plant)


class FakeGitHub:
    """In-memory GitHub Contents/Pulls/Refs stub."""

    def __init__(self, branch_files=None, pulls=None, fail_on=None):
        self.branches: dict[str, dict[str, str]] = {"main": {}}
        if branch_files:
            for b, files in branch_files.items():
                self.branches[b] = dict(files)
        self.pulls = list(pulls or [])
        self.fail_on = dict(fail_on or {})
        self.writes: list[tuple[str, str, dict | None]] = []

    def __call__(self, method: str, path: str, body: dict | None):
        base = f"/repos/{GITOPS}"
        assert path.startswith(base), path
        rest = path[len(base) :]
        bare = rest.split("?")[0]
        if method != "GET":
            self.writes.append((method, rest, body))
        if (method, bare) in self.fail_on:
            return self.fail_on[(method, bare)], None

        if method == "GET" and rest == "":
            return 200, {"default_branch": "main"}

        if rest.startswith("/git/ref/heads/"):
            b = rest[len("/git/ref/heads/") :]
            if b in self.branches:
                return 200, {"object": {"sha": f"head-{b}"}}
            return 404, None

        if method == "POST" and rest == "/git/refs":
            ref = str((body or {}).get("ref") or "")
            assert ref.startswith("refs/heads/")
            b = ref[len("refs/heads/") :]
            self.branches.setdefault(b, dict(self.branches["main"]))
            return 201, {}

        if method == "PATCH" and rest.startswith("/git/refs/heads/"):
            b = rest[len("/git/refs/heads/") :]
            if b in self.branches:
                self.branches[b] = dict(self.branches["main"])
                return 200, {}
            return 404, None

        if method == "DELETE" and rest.startswith("/git/refs/heads/"):
            b = rest[len("/git/refs/heads/") :]
            if b in self.branches:
                del self.branches[b]
                return 204, None
            return 404, None

        if rest.startswith("/contents/"):
            rel = bare[len("/contents/") :]
            if method == "GET":
                m = re.search(r"[?&]ref=([^&]+)", rest)
                b = m.group(1) if m else "main"
                files = self.branches.get(b, {})
                if rel not in files:
                    return 404, None
                encoded = base64.b64encode(files[rel].encode("utf-8")).decode("ascii")
                return 200, {"content": encoded, "sha": f"sha-{b}-{rel}"}
            if method == "PUT":
                b = str((body or {}).get("branch") or "main")
                content = base64.b64decode(str((body or {})["content"])).decode("utf-8")
                self.branches.setdefault(b, {})[rel] = content
                return 201, {}
            if method == "DELETE":
                b = str((body or {}).get("branch") or "main")
                assert (body or {}).get("sha") == f"sha-{b}-{rel}"
                del self.branches[b][rel]
                return 200, {}

        if method == "GET" and rest.startswith("/pulls?"):
            m = re.search(r"[?&]base=([^&]+)", rest)
            b = m.group(1) if m else "main"
            matched = [
                p["pull"]
                for p in self.pulls
                if p["pull"].get("state", "open") == "open"
                and (p["pull"].get("base") or {}).get("ref", "main") == b
            ]
            return 200, matched

        m_files = re.fullmatch(r"/pulls/(\d+)/files\?.*", rest)
        if method == "GET" and m_files:
            num = int(m_files.group(1))
            for p in self.pulls:
                if p["pull"]["number"] == num:
                    return 200, [{"filename": fn} for fn in p["files"]]
            return 404, None

        m_labels = re.fullmatch(r"/issues/(\d+)/labels", rest)
        if method == "POST" and m_labels:
            num = int(m_labels.group(1))
            for p in self.pulls:
                if p["pull"]["number"] == num:
                    existing = p["pull"].setdefault("labels", [])
                    for lbl in (body or {}).get("labels", []):
                        existing.append({"name": lbl})
                    return 200, existing
            return 404, None

        m_patch = re.fullmatch(r"/pulls/(\d+)", rest)
        if method == "PATCH" and m_patch:
            num = int(m_patch.group(1))
            for p in self.pulls:
                if p["pull"]["number"] == num:
                    p["pull"]["state"] = str((body or {}).get("state", "closed"))
                    return 200, p["pull"]
            return 404, None

        raise AssertionError(f"unexpected call: {method} {path}")


def _settings(tmp_path: Path, base_branch: str = "") -> plant.Settings:
    tok = tmp_path / "token"
    tok.write_text("ghs_test_token\n", encoding="utf-8")
    return plant.Settings(
        gitops_repo=GITOPS,
        cluster_name=CLUSTER,
        namespace=NAMESPACE,
        token_file=str(tok),
        base_branch=base_branch,
    )


def test_rendered_manifests_cover_all_four_preflight_shapes():
    rendered = plant.render_manifests(NAMESPACE)
    assert set(rendered) == {
        "order-processor.yaml",
        "config-watcher.yaml",
        "gcs-archiver.yaml",
        "vault-fetcher.yaml",
    }
    for name, content in rendered.items():
        docs = [d for d in yaml.safe_load_all(content) if d]
        assert docs, name
        for d in docs:
            assert d["metadata"]["labels"]["managed-by"] == "kube-agents-bench"

    # gcs-archiver carries Workload Identity annotation
    gcs_docs = list(yaml.safe_load_all(rendered["gcs-archiver.yaml"]))
    sa = next(d for d in gcs_docs if d["kind"] == "ServiceAccount")
    assert "iam.gke.io/gcp-service-account" in sa["metadata"]["annotations"]

    # config-watcher carries a RoleBinding
    cw_docs = list(yaml.safe_load_all(rendered["config-watcher.yaml"]))
    assert any(d["kind"] == "RoleBinding" for d in cw_docs)

    # vault-fetcher mounts /var/run/secrets/kubernetes.io/serviceaccount
    vf_docs = list(yaml.safe_load_all(rendered["vault-fetcher.yaml"]))
    dep = next(d for d in vf_docs if d["kind"] == "Deployment")
    mounts = dep["spec"]["template"]["spec"]["containers"][0]["volumeMounts"]
    assert any(
        m["mountPath"] == "/var/run/secrets/kubernetes.io/serviceaccount"
        for m in mounts
    )


def test_main_tf_manifest_matches_plant_render_manifests():
    main_tf = (STACK / "main.tf").read_text(encoding="utf-8")
    match = re.search(
        r"manifest\s*=\s*<<-MANIFEST\n(.*?)\n\s*MANIFEST", main_tf, flags=re.DOTALL
    )
    assert match is not None
    dedented = "\n".join(
        line[4:] if line.startswith("    ") else line
        for line in match.group(1).splitlines()
    ).replace("${var.namespace}", NAMESPACE)

    tf_objects = {}
    for doc in yaml.safe_load_all(dedented):
        if not doc:
            continue
        doc.setdefault("metadata", {})["namespace"] = NAMESPACE
        tf_objects[(doc["kind"], doc["metadata"]["name"])] = doc

    plant_objects = {}
    for content in plant.render_manifests(NAMESPACE).values():
        for doc in yaml.safe_load_all(content):
            if not doc:
                continue
            plant_objects[(doc["kind"], doc["metadata"]["name"])] = doc

    assert tf_objects == plant_objects


def test_is_owned_manifest_requires_exact_label_line():
    assert not plant.is_owned_manifest(
        "# managed-by: kube-agents-bench\napiVersion: v1\nkind: ConfigMap\n"
    )
    assert not plant.is_owned_manifest(
        "metadata:\n  labels:\n    managed-by: kube-agents-bench-other\n"
    )
    assert plant.is_owned_manifest(
        "metadata:\n  labels:\n    managed-by: kube-agents-bench\n"
    )


def test_validate_settings_and_main_fail_fast(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("SA_AUTOMOUNT_EVAL_GITOPS_REPO", raising=False)
    with pytest.raises(RuntimeError, match="missing required setting gitops_repo"):
        plant.main(["plant.py", "plant"])

    planter = plant.Planter(_settings(tmp_path, base_branch="feature-unprefixed"), FakeGitHub())
    with pytest.raises(RuntimeError, match="must start with 'eval-'"):
        planter.validate_settings()


def test_plant_and_teardown_on_default_branch(tmp_path: Path):
    gh = FakeGitHub(
        branch_files={"main": {"README.md": "# Repo\n"}},
        pulls=[
            {
                "pull": {
                    "number": 11,
                    "state": "open",
                    "base": {"ref": "main"},
                    "head": {
                        "ref": "platform-agent/sa-automount",
                        "repo": {"full_name": GITOPS},
                    },
                    "user": {"login": BOT},
                    "labels": [{"name": "audit:remediation"}],
                },
                "files": [f"{DIRECTORY}/order-processor.yaml"],
            },
            {
                "pull": {
                    "number": 12,
                    "state": "open",
                    "base": {"ref": "main"},
                    "head": {
                        "ref": "human/unrelated",
                        "repo": {"full_name": GITOPS},
                    },
                    "user": {"login": "alice"},
                    "labels": [],
                },
                "files": [f"{DIRECTORY}/order-processor.yaml"],
            },
        ],
    )
    planter = plant.Planter(_settings(tmp_path), gh)
    planter.plant()
    for fname in ("order-processor.yaml", "config-watcher.yaml", "gcs-archiver.yaml", "vault-fetcher.yaml"):
        assert f"{DIRECTORY}/{fname}" in gh.branches["main"]

    planter.teardown()
    assert set(gh.branches["main"]) == {"README.md"}
    assert gh.pulls[0]["pull"]["state"] == "closed"
    assert any(
        lbl["name"] == "audit:stale-closed" for lbl in gh.pulls[0]["pull"]["labels"]
    )
    # Human PR stays open.
    assert gh.pulls[1]["pull"]["state"] == "open"


def test_plant_rolls_back_created_eval_branch_when_first_put_fails(tmp_path: Path):
    gh = FakeGitHub(
        branch_files={"main": {"README.md": "# Live Repo\n"}},
        fail_on={("PUT", f"/contents/{DIRECTORY}/order-processor.yaml"): 500},
    )
    planter = plant.Planter(_settings(tmp_path, base_branch="eval-sa-automount-base"), gh)
    with pytest.raises(RuntimeError, match="PUT contents"):
        planter.plant()
    assert "eval-sa-automount-base" not in gh.branches


def test_teardown_skips_fork_prs_and_removes_main_files_even_if_pr_close_fails(
    tmp_path: Path,
):
    gh = FakeGitHub(
        branch_files={"main": {"README.md": "# Repo\n"}},
        pulls=[
            {
                "pull": {
                    "number": 21,
                    "state": "open",
                    "base": {"ref": "main"},
                    "head": {
                        "ref": "fork-branch",
                        "repo": {"full_name": "external-fork/kube-agents-evals-2-infra"},
                    },
                    "user": {"login": BOT},
                    "labels": [],
                },
                "files": [f"{DIRECTORY}/order-processor.yaml"],
            },
            {
                "pull": {
                    "number": 22,
                    "state": "open",
                    "base": {"ref": "main"},
                    "head": {
                        "ref": "platform-agent/sa-automount",
                        "repo": {"full_name": GITOPS},
                    },
                    "user": {"login": BOT},
                    "labels": [],
                },
                "files": [f"{DIRECTORY}/order-processor.yaml"],
            },
        ],
        fail_on={("PATCH", "/pulls/22"): 500},
    )
    planter = plant.Planter(_settings(tmp_path), gh)
    planter.plant()
    with pytest.raises(RuntimeError, match="closing PR #22"):
        planter.teardown()
    # Fork PR untouched; default-branch files still cleaned up in finally block.
    assert gh.pulls[0]["pull"]["state"] == "open"
    assert set(gh.branches["main"]) == {"README.md"}


def test_refuses_to_overwrite_unowned_file(tmp_path: Path):
    gh = FakeGitHub(
        branch_files={
            "main": {f"{DIRECTORY}/order-processor.yaml": "apiVersion: v1\nkind: ConfigMap\n"}
        }
    )
    planter = plant.Planter(_settings(tmp_path), gh)
    with pytest.raises(RuntimeError, match="unowned file"):
        planter.plant()


def test_isolated_base_branch_leaves_main_untouched(tmp_path: Path):
    gh = FakeGitHub(branch_files={"main": {"README.md": "# Live Repo\n"}})
    planter = plant.Planter(_settings(tmp_path, base_branch="eval-sa-automount-base"), gh)
    planter.plant()
    assert set(gh.branches["main"]) == {"README.md"}
    assert f"{DIRECTORY}/order-processor.yaml" in gh.branches["eval-sa-automount-base"]

    # Re-planting resets an existing eval-* branch cleanly.
    gh.branches["eval-sa-automount-base"]["stale.yaml"] = "stale: true\n"
    planter.plant()
    assert "stale.yaml" not in gh.branches["eval-sa-automount-base"]

    planter.teardown()
    assert "eval-sa-automount-base" not in gh.branches
    assert set(gh.branches["main"]) == {"README.md"}


def test_stack_declares_runner_gitops_write_marker_and_matches_task():
    variables_tf = (STACK / "variables.tf").read_text(encoding="utf-8")
    main_tf = (STACK / "main.tf").read_text(encoding="utf-8")
    task = yaml.safe_load(TASK.read_text(encoding="utf-8"))

    assert 'variable "bench_gitops_write_token_file"' in variables_tf
    assert "var.bench_gitops_write_token_file" in main_tf
    assert task["infrastructure"]["stack"] == "prebuilt/security-unused-sa-token-automount"
    assert task["writes_alone"] is True

    pr_checks = [
        entry["check"]
        for entry in task["verification_spec"]
        if entry["check"].get("type") == "pull_request_opened"
    ]
    assert len(pr_checks) == 1
    assert pr_checks[0]["changed_paths_only"] == [
        "clusters/*/namespaces/seeded-sa-automount/order-processor.yaml"
    ]
