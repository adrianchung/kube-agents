#!/usr/bin/env python3
"""Count the Hermes touchpoints that `hack/patch-metric.sh` cannot see.

`patch-metric.sh` counts build-time patch sets by globbing `apply_*.py`. That is
the visible part of the coupling and not the largest part: the same build also
rewrites Hermes source inline from the Dockerfile, monkey patches vendored chat
adapters at import time via `sitecustomize.py`, imports Hermes internals from
inside plugins, and opens a Hermes-owned SQLite database directly. None of that
moves the patch-set count, so none of it shows up in the ratchet.

This module counts those four, and `patch-metric.sh` folds the numbers into the
one table and the one baseline file so there is a single ratchet rather than
two. `docs/designs/hermes-touchpoints.md` is the prose inventory these counts
must agree with; if they diverge, one of the two is stale.

Why Python rather than more bash: three of the four counts are questions about
Python syntax ("which attribute does this assign", "what does this import"), and
a grep for them is a guess that reformatting can break. `ast` answers them
exactly, and the stdlib is already a hard dependency of `make test-python`.

## What these numbers are, and are not

Each count is the crudest measure that cannot be gamed by reformatting, and its
absolute value carries less meaning than its direction. `sitecustomize_targets`
in particular counts assignment *sites*, not distinct attributes: both relay
patches rebind `PlatformRegistry.create_adapter`, chained, and deleting one of
them is real progress that a distinct-attribute count would report as no change.

Every counter fails loudly rather than returning a zero it cannot justify. A
scan whose root moved reports 0, and 0 is indistinguishable from success at the
exact moment the check stopped working — so a counter that expects to match
something says so, and raises when it does not.

Usage:
    hermes_touchpoints.py            # a table of the counts
    hermes_touchpoints.py --list     # the counts plus what each one matched
    hermes_touchpoints.py --env      # KEY=value lines for patch-metric.sh
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DOCKERFILE = Path("deploy/docker/Dockerfile")
SITECUSTOMIZE = Path("agents/platform/scripts/sitecustomize.py")

# Hermes ships its own source at /opt/hermes; an inline edit is one that rewrites
# a file under that prefix without going through an applier script.
HERMES_INSTALL_PREFIX = "/opt/hermes/"

# Top-level module names that belong to Hermes rather than to this repository or
# the standard library. Importing one of these from a plugin is reaching past
# the documented `register(ctx)` plugin API into the harness itself, which is the
# thing being counted. Kept explicit rather than inferred: several of these names
# (`agent`, `tools`, `utils`, `plugins`) are generic enough that a heuristic
# would guess, and a ratchet that guesses is a ratchet that argues.
HERMES_INTERNAL_ROOTS = frozenset(
    {
        "agent",
        "cron",
        "gateway",
        "hermes_cli",
        "hermes_plugins",
        "plugins",
        "tools",
        "utils",
    }
)

# Directories whose Python is shipped *into* /opt/hermes as part of a patch set.
# Those modules die with the patch set that installs them and are already counted
# by `apply_sets`; counting them again here would double-charge the same coupling.
PATCH_PAYLOAD_DIR = Path("deploy/docker/patches")

# Tables owned by Hermes' schema. Opening these from this repository means an
# upstream migration is silent data corruption rather than an import error.
HERMES_OWNED_TABLES = ("kanban_notify_subs",)


class ScanError(RuntimeError):
    """A counter could not run. Never reported as a count of zero."""


def _read(path: Path) -> str:
    full = REPO_ROOT / path
    if not full.exists():
        raise ScanError(
            f"{path} does not exist - the scan cannot run. If it moved, update "
            f"this script; do not let the count silently drop to zero."
        )
    return full.read_text(encoding="utf-8")


def _python_files(directory: Path) -> list[Path]:
    full = REPO_ROOT / directory
    if not full.is_dir():
        raise ScanError(f"{directory} is not a directory - the scan cannot run.")
    return sorted(p for p in full.rglob("*.py"))


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


# ------------------------------------------------------------------------------
# 1. Hermes source the Dockerfile rewrites inline, with no applier
# ------------------------------------------------------------------------------


def _run_blocks(dockerfile: str) -> list[str]:
    """Split a Dockerfile into logical instructions, honouring line continuations."""
    blocks: list[str] = []
    current: list[str] = []
    for line in dockerfile.splitlines():
        current.append(line)
        if not line.rstrip().endswith("\\"):
            blocks.append("\n".join(current))
            current = []
    if current:
        blocks.append("\n".join(current))
    return blocks


_HERMES_PY_PATH = re.compile(r"/opt/hermes/[\w./-]+\.py")


def count_dockerfile_inline_edits() -> tuple[int, list[str]]:
    """Distinct Hermes source files the Dockerfile edits in place.

    An applier under `deploy/docker/patches/` is the supported way to do this:
    it anchors on exact source text, gates on `ast.parse`, and fails the build
    when upstream drifts. An inline `sed`/`python3 -c` in a RUN line does the
    same surgery with none of that, and `apply_*.py` globbing cannot see it.

    Counts distinct target *files* rather than edits, because "how many upstream
    files does the build rewrite by hand" is the quantity that has to reach zero;
    two anchors into one file are one file's worth of drift risk.
    """
    dockerfile = _read(DOCKERFILE)
    edited: dict[str, str] = {}
    for block in _run_blocks(dockerfile):
        if "apply_" in block:
            continue  # an applier's RUN block; already counted as a patch set
        if "sed -i" not in block and "write_text" not in block:
            continue  # reads and smoke tests, not rewrites
        for path in _HERMES_PY_PATH.findall(block):
            edited.setdefault(path, block.splitlines()[0][:88])

    if not edited:
        raise ScanError(
            "found zero inline Hermes source edits in the Dockerfile. Either they "
            "all went away (celebrate, then lower the baseline) or this scan no "
            "longer recognises how the Dockerfile writes files."
        )
    return len(edited), [f"{p}  ({where})" for p, where in sorted(edited.items())]


# ------------------------------------------------------------------------------
# 2. Runtime monkey patch targets installed by sitecustomize.py
# ------------------------------------------------------------------------------


def _relay_patch_modules() -> list[Path]:
    """The patch installers `sitecustomize.py` imports.

    Discovered from the source rather than hardcoded, so a third installer is
    counted the day it is added instead of the day someone remembers this file.
    """
    tree = ast.parse(_read(SITECUSTOMIZE))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])

    modules = []
    for name in sorted(n for n in names if n.endswith("_patch")):
        candidate = SITECUSTOMIZE.parent / f"{name}.py"
        if not (REPO_ROOT / candidate).exists():
            raise ScanError(
                f"{SITECUSTOMIZE} imports {name!r} but "
                f"{candidate} does not exist - the scan cannot read its targets."
            )
        modules.append(candidate)

    if not modules:
        raise ScanError(
            f"{SITECUSTOMIZE} imports no *_patch module. Either the monkey "
            f"patching is gone (lower the baseline) or the naming changed and "
            f"this scan is now blind to it."
        )
    return modules


def _is_patch_target(node: ast.AST) -> str | None:
    """Return `receiver.attribute` if this statement rebinds someone else's attribute.

    Two exclusions, both deliberate:

    Anything rooted at `self` is ordinary object state set inside a replacement
    method, not a patch. Counting it would make a longer replacement look like
    more coupling. The whole chain is checked, not just `self.<attr>`, because
    the Slack installer's replacements assign `self.config.token`.

    `<obj>._..._patched` is the idempotency marker each installer sets so a second
    import is a no-op. It is bookkeeping about patching rather than a patch, and
    it would inflate every installer by a constant.
    """
    if not isinstance(node, ast.Assign) or len(node.targets) != 1:
        return None
    target = node.targets[0]
    if not isinstance(target, ast.Attribute):
        return None
    root = target.value
    while isinstance(root, ast.Attribute):
        root = root.value
    if isinstance(root, ast.Name) and root.id == "self":
        return None
    if target.attr.endswith("_patched"):
        return None
    return f"{ast.unparse(target.value)}.{target.attr}"


def count_sitecustomize_targets() -> tuple[int, list[str]]:
    """Attribute-assignment sites in the installers `sitecustomize.py` runs.

    Sites, not distinct attributes: both relay patches rebind
    `PlatformRegistry.create_adapter`, chained one over the other, so deleting
    either one is progress a distinct-attribute count would round away to zero.
    """
    evidence = []
    for module in _relay_patch_modules():
        tree = ast.parse(_read(module))
        found = [t for node in ast.walk(tree) if (t := _is_patch_target(node))]
        if not found:
            raise ScanError(
                f"{module} is imported by sitecustomize.py but assigns no "
                f"attributes. Either it stopped monkey patching (lower the "
                f"baseline) or it found a way this scan does not recognise."
            )
        evidence.extend(f"{_rel(REPO_ROOT / module)}: {t}" for t in sorted(found))
    return len(evidence), evidence


# ------------------------------------------------------------------------------
# 3. Plugins importing Hermes internals
# ------------------------------------------------------------------------------


def _plugin_units() -> list[Path]:
    """Every directory this repository ships as a plugin or hook.

    Identified by its manifest, which is what Hermes itself loads them by.
    """
    units = sorted(
        {
            manifest.parent
            for pattern in ("plugin.yaml", "HOOK.yaml")
            for manifest in REPO_ROOT.rglob(pattern)
            if PATCH_PAYLOAD_DIR.as_posix() not in manifest.as_posix()
            and "/node_modules/" not in manifest.as_posix()
        }
    )
    if not units:
        raise ScanError(
            "found no plugin.yaml or HOOK.yaml anywhere in the repository. The "
            "plugins did not vanish; this scan did."
        )
    return units


def _hermes_imports(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots & HERMES_INTERNAL_ROOTS


def count_plugins_importing_internals() -> tuple[int, list[str]]:
    """Plugins that reach past the `register(ctx)` API into Hermes' own modules.

    Using the plugin API is not coupling; it is the supported interface and it
    survives the runner boundary. Importing `gateway.session_context` from inside
    a plugin is coupling, because nothing upstream promises it will still be
    there. Counted per plugin rather than per import: one plugin reaching for six
    modules is one thing to port.
    """
    evidence = []
    for unit in _plugin_units():
        roots: set[str] = set()
        for source_file in sorted(unit.rglob("*.py")):
            roots |= _hermes_imports(source_file.read_text(encoding="utf-8"))
        if roots:
            evidence.append(f"{_rel(unit)}: {', '.join(sorted(roots))}")
    return len(evidence), evidence


# ------------------------------------------------------------------------------
# 4. Repository code opening Hermes-owned SQLite tables
# ------------------------------------------------------------------------------


def count_direct_table_access() -> tuple[int, list[str]]:
    """Repository-owned modules that open a Hermes database and name its tables.

    Excludes `deploy/docker/patches/`: that code is shipped inside /opt/hermes as
    part of a patch set and dies with it, so `apply_sets` already charges for it.
    Excludes tests, which have to name the tables to build a fixture board.
    """
    evidence = []
    for source_file in _python_files(Path("agents")) + _python_files(Path("scripts")):
        if PATCH_PAYLOAD_DIR.as_posix() in source_file.as_posix():
            continue
        if source_file.name.startswith("test_"):
            continue
        source = source_file.read_text(encoding="utf-8")
        if "sqlite3" not in source:
            continue
        tables = [t for t in HERMES_OWNED_TABLES if t in source]
        if tables:
            evidence.append(f"{_rel(source_file)}: {', '.join(tables)}")
    return len(evidence), evidence


# ------------------------------------------------------------------------------
# The registry
# ------------------------------------------------------------------------------

COUNTERS = (
    (
        "HERMES_TOUCHPOINT_DOCKERFILE_EDITS",
        "Inline Hermes source edits (Dockerfile)",
        count_dockerfile_inline_edits,
    ),
    (
        "HERMES_TOUCHPOINT_SITECUSTOMIZE_TARGETS",
        "Runtime monkey patch targets (sitecustomize)",
        count_sitecustomize_targets,
    ),
    (
        "HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS",
        "Plugins importing Hermes internals",
        count_plugins_importing_internals,
    ),
    (
        "HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS",
        "Repository code opening Hermes tables",
        count_direct_table_access,
    ),
)


def measure() -> dict[str, tuple[int, list[str]]]:
    """Run every counter. Raises ScanError rather than reporting an unjustified zero."""
    return {key: fn() for key, _, fn in COUNTERS}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--env",
        action="store_true",
        help="emit KEY=value lines for hack/patch-metric.sh to source",
    )
    parser.add_argument(
        "--list", action="store_true", help="show what each counter matched"
    )
    args = parser.parse_args(argv)

    try:
        results = measure()
    except ScanError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if args.env:
        for key, _, _ in COUNTERS:
            print(f"{key}={results[key][0]}")
        return 0

    width = max(len(label) for _, label, _ in COUNTERS)
    for key, label, _ in COUNTERS:
        count, evidence = results[key]
        print(f"{label.ljust(width)}  {count:>3}")
        if args.list:
            for item in evidence:
                print(f"{' ' * (width + 4)}- {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
