#!/usr/bin/env python3
"""Tests for the Hermes touchpoint counters.

Two halves, and the second is the one that matters.

`AgainstThisRepository` pins the counters to the checked-in baseline, so the
ratchet and the numbers it ratchets cannot drift apart silently.

`TheScansActuallyMatch` builds a synthetic repository, adds one touchpoint of
each kind, and asserts the count moves. A counter that reports zero because its
scan root moved is indistinguishable from a counter reporting total success, and
the first half of this file would pass either way once someone lowered the
baseline to match. Every counter therefore has to prove it can still see.
"""

from __future__ import annotations

import re
import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.absolute()))

import hermes_touchpoints as ht  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BASELINE_FILE = REPO / "hack" / "patch-metric-baseline.env"
METRIC_SCRIPT = REPO / "hack" / "patch-metric.sh"

# Each counter, paired with the baseline variable patch-metric.sh compares it to.
COUNTER_BASELINES = {
    "HERMES_TOUCHPOINT_DOCKERFILE_EDITS": "BASELINE_DOCKERFILE_EDITS",
    "HERMES_TOUCHPOINT_SITECUSTOMIZE_TARGETS": "BASELINE_SITECUSTOMIZE_TARGETS",
    "HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS": "BASELINE_INTERNAL_IMPORT_PLUGINS",
    "HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS": "BASELINE_DIRECT_TABLE_ACCESS",
}


def read_baselines() -> dict[str, int]:
    values = {}
    for line in BASELINE_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("BASELINE_") and "=" in line:
            key, _, value = line.partition("=")
            values[key] = int(value)
    return values


class AgainstThisRepository(unittest.TestCase):
    """The counters, run over the real tree."""

    @classmethod
    def setUpClass(cls):
        cls.results = ht.measure()
        cls.baselines = read_baselines()

    def test_every_counter_matches_its_checked_in_baseline(self):
        for key, baseline_key in COUNTER_BASELINES.items():
            with self.subTest(key):
                self.assertIn(
                    baseline_key,
                    self.baselines,
                    f"{baseline_key} is missing from {BASELINE_FILE.name}; "
                    f"patch-metric.sh would exit on an unbound variable.",
                )
                self.assertEqual(
                    self.baselines[baseline_key],
                    self.results[key][0],
                    f"{key} moved. If coupling was removed, run "
                    f"'bash hack/patch-metric.sh --update'. If it was added, "
                    f"that is the regression this ratchet exists to catch.",
                )

    def test_no_counter_reports_zero(self):
        """Zero is what a broken scan and a finished migration look like alike.

        Each counter raises rather than returning an unjustified zero, so this
        is really asserting that none of them has silently started to. When a
        touchpoint class genuinely reaches zero, delete its counter in the same
        change that earns it -- do not weaken this test.
        """
        for key, (count, _) in self.results.items():
            with self.subTest(key):
                self.assertGreater(count, 0, f"{key} counted nothing")

    def test_every_count_names_what_it_counted(self):
        for key, (count, evidence) in self.results.items():
            with self.subTest(key):
                self.assertEqual(count, len(evidence))

    def test_the_metric_script_reads_exactly_the_baselines_it_writes(self):
        """`--update` rewrites the whole baseline file from a heredoc.

        A heredoc that emits a subset of the variables the script reads deletes
        the rest, and the next run exits on an unbound variable. This compares
        the two sets directly, because the failure only shows up on the next
        `--update` -- long after the change that caused it.
        """
        script = METRIC_SCRIPT.read_text(encoding="utf-8")
        heredoc = script.split("cat > \"$BASELINE_FILE\" <<EOF", 1)
        self.assertEqual(len(heredoc), 2, "the --update heredoc moved or was renamed")
        written = set(re.findall(r"^(BASELINE_\w+)=", heredoc[1], re.MULTILINE))
        # BASELINE_FILE is the path to the file, not a count that lives in it.
        read = set(re.findall(r"\$(BASELINE_\w+)\b", script)) - {"BASELINE_FILE"}
        self.assertEqual(
            read,
            written,
            "patch-metric.sh reads and writes different baseline variables",
        )


class SyntheticRepo:
    """The smallest tree every counter can run against without raising."""

    def __init__(self, root: Path):
        self.root = root
        (root / "agents/platform/scripts").mkdir(parents=True)
        (root / "deploy/docker").mkdir(parents=True)
        (root / "scripts").mkdir(parents=True)

        self.write(
            "deploy/docker/Dockerfile",
            """
            FROM base
            RUN sed -i 's/a/b/' /opt/hermes/one.py
            RUN /opt/hermes/.venv/bin/python3 /tmp/apply_thing.py /opt/hermes && \\
                grep -q "x" /opt/hermes/excluded_by_applier.py
            RUN /opt/hermes/.venv/bin/python3 -c "p.write_text(c)" /opt/other/two.py
            """,
        )
        self.write(
            "agents/platform/scripts/sitecustomize.py",
            "import example_relay_patch\nexample_relay_patch.install()\n",
        )
        self.write(
            "agents/platform/scripts/example_relay_patch.py",
            """
            def install():
                adapter_class.connect = connect
                adapter_class._relay_patched = True
                self.config.token = "x"
            """,
        )
        self.add_plugin("clean_plugin", "import json\n")
        self.write("scripts/unrelated.py", "import json\n")

    def write(self, relative: str, body: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        return path

    def add_plugin(self, name: str, body: str) -> None:
        self.write(f"agents/chat/defaults/plugins/{name}/plugin.yaml", "name: x\n")
        self.write(f"agents/chat/defaults/plugins/{name}/plugin.py", body)


class TheScansActuallyMatch(unittest.TestCase):
    """Add one touchpoint of each kind; the matching counter must notice.

    Without these, a counter whose scan root moved reads as a clean repository.
    """

    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = SyntheticRepo(Path(self._tmp.name))

        original = ht.REPO_ROOT
        ht.REPO_ROOT = self.repo.root
        self.addCleanup(lambda: setattr(ht, "REPO_ROOT", original))

    def counts(self) -> dict[str, int]:
        return {key: count for key, (count, _) in ht.measure().items()}

    def test_the_baseline_synthetic_repo_counts_what_it_contains(self):
        self.assertEqual(
            {
                "HERMES_TOUCHPOINT_DOCKERFILE_EDITS": 1,
                "HERMES_TOUCHPOINT_SITECUSTOMIZE_TARGETS": 1,
                "HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS": 0,
                "HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS": 0,
            },
            self.counts(),
        )

    def test_an_applier_run_block_is_not_an_inline_edit(self):
        """The fixture's applier block names a Hermes .py; it must not be counted."""
        _, evidence = ht.count_dockerfile_inline_edits()
        self.assertNotIn("excluded_by_applier", " ".join(evidence))

    def test_an_edit_outside_opt_hermes_is_not_counted(self):
        _, evidence = ht.count_dockerfile_inline_edits()
        self.assertNotIn("/opt/other/two.py", " ".join(evidence))

    def test_a_new_inline_dockerfile_edit_is_counted(self):
        dockerfile = self.repo.root / "deploy/docker/Dockerfile"
        dockerfile.write_text(
            dockerfile.read_text() + "RUN sed -i 's/c/d/' /opt/hermes/three.py\n"
        )
        self.assertEqual(2, self.counts()["HERMES_TOUCHPOINT_DOCKERFILE_EDITS"])

    def test_two_edits_to_one_file_stay_one_touchpoint(self):
        dockerfile = self.repo.root / "deploy/docker/Dockerfile"
        dockerfile.write_text(
            dockerfile.read_text() + "RUN sed -i 's/c/d/' /opt/hermes/one.py\n"
        )
        self.assertEqual(1, self.counts()["HERMES_TOUCHPOINT_DOCKERFILE_EDITS"])

    def test_a_new_monkey_patch_target_is_counted(self):
        patch = self.repo.root / "agents/platform/scripts/example_relay_patch.py"
        patch.write_text(patch.read_text() + "    adapter_class.disconnect = off\n")
        self.assertEqual(2, self.counts()["HERMES_TOUCHPOINT_SITECUSTOMIZE_TARGETS"])

    def test_a_second_installer_is_discovered_from_sitecustomize(self):
        """The installer list is read from the source, not hardcoded here."""
        self.repo.write(
            "agents/platform/scripts/second_relay_patch.py",
            "def install():\n    Registry.create_adapter = make\n",
        )
        site = self.repo.root / "agents/platform/scripts/sitecustomize.py"
        site.write_text(site.read_text() + "import second_relay_patch\n")
        self.assertEqual(2, self.counts()["HERMES_TOUCHPOINT_SITECUSTOMIZE_TARGETS"])

    def test_an_installer_sitecustomize_imports_but_that_is_missing_raises(self):
        site = self.repo.root / "agents/platform/scripts/sitecustomize.py"
        site.write_text(site.read_text() + "import absent_relay_patch\n")
        with self.assertRaises(ht.ScanError):
            ht.count_sitecustomize_targets()

    def test_a_plugin_importing_a_hermes_internal_is_counted(self):
        self.repo.add_plugin("reaching", "from gateway.session_context import ctx\n")
        self.assertEqual(1, self.counts()["HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS"])

    def test_a_plugin_reaching_for_six_modules_is_still_one_touchpoint(self):
        self.repo.add_plugin(
            "deep", "import gateway\nimport tools\nimport agent\nimport cron\n"
        )
        self.assertEqual(1, self.counts()["HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS"])

    def test_a_hook_counts_the_same_as_a_plugin(self):
        self.repo.write("agents/chat/defaults/hooks/h/HOOK.yaml", "name: h\n")
        self.repo.write("agents/chat/defaults/hooks/h/hook.py", "import hermes_cli\n")
        self.assertEqual(1, self.counts()["HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS"])

    def test_a_relative_import_inside_a_plugin_is_not_a_hermes_import(self):
        """`from . import agent` is the plugin's own module, not Hermes'."""
        self.repo.add_plugin("local", "from . import agent\nfrom .tools import x\n")
        self.assertEqual(0, self.counts()["HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS"])

    def test_a_script_opening_a_hermes_table_is_counted(self):
        self.repo.write(
            "agents/platform/scripts/board.py",
            "import sqlite3\nsqlite3.connect(p).execute('SELECT 1 FROM "
            "kanban_notify_subs')\n",
        )
        self.assertEqual(1, self.counts()["HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS"])

    def test_naming_a_hermes_table_without_sqlite3_is_not_direct_access(self):
        self.repo.write(
            "agents/platform/scripts/prose.py",
            "DOC = 'the notifier reads kanban_notify_subs'\n",
        )
        self.assertEqual(0, self.counts()["HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS"])

    def test_a_patch_payload_module_is_not_double_counted(self):
        """`deploy/docker/patches/` ships into /opt/hermes and dies with its patch set."""
        self.repo.write(
            "deploy/docker/patches/kanban_thing.py",
            "import sqlite3\n# INSERT INTO kanban_notify_subs\n",
        )
        self.repo.write("deploy/docker/patches/plugin.yaml", "name: shipped\n")
        counts = self.counts()
        self.assertEqual(0, counts["HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS"])
        self.assertEqual(0, counts["HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS"])

    def test_a_test_file_naming_a_table_is_not_direct_access(self):
        self.repo.write(
            "agents/platform/scripts/test_board.py",
            "import sqlite3\nsqlite3.connect(':memory:').execute("
            "'CREATE TABLE kanban_notify_subs (x)')\n",
        )
        self.assertEqual(0, self.counts()["HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS"])


class ScansRefuseToGuess(unittest.TestCase):
    """A missing scan root is an error, never a count of zero."""

    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        original = ht.REPO_ROOT
        ht.REPO_ROOT = Path(self._tmp.name)
        self.addCleanup(lambda: setattr(ht, "REPO_ROOT", original))

    def test_every_counter_raises_on_an_empty_tree(self):
        for _, label, counter in ht.COUNTERS:
            with self.subTest(label):
                try:
                    count, _ = counter()
                except ht.ScanError:
                    continue
                self.fail(f"{label} returned {count} instead of raising")


if __name__ == "__main__":
    unittest.main()
