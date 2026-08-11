#!/usr/bin/env bash
# ==============================================================================
# 📉 Hermes coupling metric - a ratchet that may only turn one way
# ==============================================================================
# This repository consumes upstream `nousresearch/hermes-agent` as an image and
# then rewrites its internals at build time: 13 `apply_*.py` patch sets, each
# anchored to source text in files we do not own. That is a fork maintained
# inside a Dockerfile, and every upstream bump is a bet that the anchors still
# hold.
#
# The patch sets are the visible part of the coupling and not the largest part.
# The same build also rewrites Hermes source inline from the Dockerfile, monkey
# patches vendored chat adapters at import time, imports Hermes internals from
# inside plugins, and opens a Hermes-owned SQLite database directly. Those four
# are counted by `hack/hermes_touchpoints.py` -- three of them are questions
# about Python syntax, which `ast` answers exactly and a grep only guesses at --
# and folded into the table below. `python3 hack/hermes_touchpoints.py --list`
# names every touchpoint behind those four counts.
#
# The harness-v2 direction is to move the responsibilities we patch hardest
# (cron, kanban, chat adapters, approvals) out of Hermes, so every one of those
# counts falls to zero. "Coupling is shrinking" is only a claim until something
# counts it, so this script counts it, and CI prints the number on every pull
# request.
#
# The ratchet: a count may never exceed its checked-in baseline. Going *under*
# the baseline is the point of the exercise -- when that happens the script says
# so and `--update` writes the lower number back. `--update` refuses to raise
# any baseline, which is what makes this a ratchet rather than a thermometer.
#
# Portable to bash 3.2 (macOS) as well as CI. Fails loudly rather than skipping
# a check it cannot run: a metric that silently reports 0 because a path moved
# would read as total success at the exact moment it stopped working.
# ==============================================================================

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

BASELINE_FILE="hack/patch-metric-baseline.env"
PATCH_DIR="deploy/docker/patches"
DOCKERFILE="deploy/docker/Dockerfile"
TOUCHPOINTS="hack/hermes_touchpoints.py"

UPDATE=0
SUMMARY_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE=1 ;;
    --summary-only) SUMMARY_ONLY=1 ;;
    -h | --help)
      sed -n '2,33p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument '$arg' (want --update, --summary-only)" >&2
      exit 2
      ;;
  esac
done

for required in "$PATCH_DIR" "$DOCKERFILE" "$BASELINE_FILE" "$TOUCHPOINTS"; do
  if [ ! -e "$required" ]; then
    echo "ERROR: '$required' does not exist - the metric cannot run." >&2
    echo "       If it moved, update this script; do not let the count silently drop." >&2
    exit 1
  fi
done

# ------------------------------------------------------------------------------
# Measurement
# ------------------------------------------------------------------------------
# Each metric is deliberately the crudest thing that cannot be gamed by
# reformatting. `dockerfile_patch_refs` counts *lines* mentioning a patch
# script, comments included, exactly as `grep -c apply_` does; it is a coarse
# proxy for "how much of the Dockerfile is patch machinery" and its absolute
# value means nothing. Only the direction of travel does.

count_files() { # <glob-prefix> -> number of matching files in PATCH_DIR
  # shellcheck disable=SC2012 # names here are known-safe; ls is enough
  ls "$PATCH_DIR"/"$1"*.py 2>/dev/null | wc -l | tr -d ' '
}

apply_sets=$(count_files "apply_")
verify_sets=$(count_files "verify_")
dockerfile_patch_refs=$(grep -c "apply_" "$DOCKERFILE" | tr -d ' ')

# The four counts above this line are the ones a glob and a grep can answer. The
# rest of the coupling is a question about Python syntax -- which attribute does
# this rebind, what does this import -- so it is measured by ast in
# hack/hermes_touchpoints.py and folded in here. One command, one baseline, one
# table: two ratchets is one ratchet nobody runs.
#
# A failure there is fatal rather than skipped. The failure mode it protects
# against is a scan whose root moved reporting zero, and zero is what total
# success looks like.
if ! touchpoint_env=$(python3 "$TOUCHPOINTS" --env 2>&1); then
  echo "ERROR: $TOUCHPOINTS could not run:" >&2
  echo "$touchpoint_env" >&2
  exit 1
fi
eval "$touchpoint_env"

if [ "$apply_sets" -eq 0 ]; then
  echo "ERROR: found zero apply_*.py under $PATCH_DIR." >&2
  echo "       Either the patches all went away (celebrate, then run --update)," >&2
  echo "       or the glob is stale. Refusing to report a zero it cannot justify." >&2
  exit 1
fi

# Every apply_*.py is expected to have a verify_*.py beside it, because the
# verifier is what proves at build time that the anchors still matched. Two
# appliers legitimately break the naming rule; they are listed here with their
# reason so that this check stays quiet in the steady state and only speaks up
# when a *new* patch set arrives without a verifier. A warning that is always
# on is a warning nobody reads.
#
#   kanban_result_required -> verified by verify_kanban_result.py. Deliberate:
#       the Dockerfile comment at the COPY explains that the notifier patch took
#       the longer name and this verifier kept the shorter one.
#   mcp_remote_forward_errors -> no build-time verifier, and it is the one
#       applier that does not patch Hermes at all: it rewrites /opt/mcp-remote.
#       Covered instead by test_apply_mcp_remote_forward_errors.py in the
#       `make test-python` suite.
UNPAIRED_EXPECTED="kanban_result_required mcp_remote_forward_errors"

unpaired=""
for applier in "$PATCH_DIR"/apply_*.py; do
  stem=$(basename "$applier" .py)
  stem=${stem#apply_}
  [ -f "$PATCH_DIR/verify_${stem}.py" ] && continue
  case " $UNPAIRED_EXPECTED " in
    *" $stem "*) continue ;;
  esac
  unpaired="${unpaired}${unpaired:+, }${stem}"
done

# ------------------------------------------------------------------------------
# Comparison against the baseline
# ------------------------------------------------------------------------------
# shellcheck source=hack/patch-metric-baseline.env
. "./$BASELINE_FILE"

REGRESSED=0
IMPROVED=0
REPORT=""

compare() { # <label> <actual> <baseline>
  local label="$1" actual="$2" baseline="$3" mark
  if [ "$actual" -gt "$baseline" ]; then
    mark="🔴 up from $baseline - coupling grew"
    REGRESSED=1
  elif [ "$actual" -lt "$baseline" ]; then
    mark="🟢 down from $baseline - ratchet me"
    IMPROVED=1
  else
    mark="⚪️ at baseline"
  fi
  REPORT="${REPORT}| ${label} | ${actual} | ${baseline} | ${mark} |
"
}

REPORT="| Metric | Now | Baseline | |
| --- | --- | --- | --- |
"
compare "Hermes patch sets (apply_\*.py)" "$apply_sets" "$BASELINE_APPLY_SETS"
compare "Patch verifiers (verify_\*.py)" "$verify_sets" "$BASELINE_VERIFY_SETS"
compare "Dockerfile patch references" "$dockerfile_patch_refs" "$BASELINE_DOCKERFILE_PATCH_REFS"
compare "Inline Hermes source edits (Dockerfile)" \
  "$HERMES_TOUCHPOINT_DOCKERFILE_EDITS" "$BASELINE_DOCKERFILE_EDITS"
compare "Monkey patch targets (sitecustomize)" \
  "$HERMES_TOUCHPOINT_SITECUSTOMIZE_TARGETS" "$BASELINE_SITECUSTOMIZE_TARGETS"
compare "Plugins importing Hermes internals" \
  "$HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS" "$BASELINE_INTERNAL_IMPORT_PLUGINS"
compare "Repository code opening Hermes tables" \
  "$HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS" "$BASELINE_DIRECT_TABLE_ACCESS"

printf '%s' "$REPORT"

# One number for the CI summary line and for a human asking "is it going down".
# It adds up quantities with different units, which is meaningless as a level and
# is not the point: the point is that it can only fall, and every term in it can
# only fall, so nothing can hide behind an offsetting move somewhere else.
touchpoint_total=$((apply_sets + HERMES_TOUCHPOINT_DOCKERFILE_EDITS \
  + HERMES_TOUCHPOINT_SITECUSTOMIZE_TARGETS \
  + HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS \
  + HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS))
baseline_total=$((BASELINE_APPLY_SETS + BASELINE_DOCKERFILE_EDITS \
  + BASELINE_SITECUSTOMIZE_TARGETS + BASELINE_INTERNAL_IMPORT_PLUGINS \
  + BASELINE_DIRECT_TABLE_ACCESS))
echo
echo "Hermes touchpoints: $touchpoint_total (baseline $baseline_total)"
echo "Run 'python3 $TOUCHPOINTS --list' to see what each one matched."

if [ -n "$unpaired" ]; then
  echo
  echo "⚠️  New apply_*.py with no verify_*.py beside it: $unpaired"
  echo "    Add a verifier, or record the exception in UNPAIRED_EXPECTED with a reason."
  REGRESSED=1
fi

# ------------------------------------------------------------------------------
# --update: lower the baseline, never raise it
# ------------------------------------------------------------------------------
if [ "$UPDATE" -eq 1 ]; then
  if [ "$REGRESSED" -eq 1 ]; then
    echo
    echo "ERROR: --update refuses to raise a baseline. That is the whole point of" >&2
    echo "       the ratchet: a milestone that adds a patch set is mis-designed" >&2
    echo "       (implementation.md section 0.4). Stop and re-plan instead." >&2
    exit 1
  fi
  if [ "$IMPROVED" -eq 0 ]; then
    echo
    echo "Nothing to update: every count is already at its baseline."
    exit 0
  fi
  # Every baseline is rewritten, not just the ones that moved: a heredoc that
  # emits a subset deletes the rest. `set -u` turns a deleted baseline into an
  # unbound-variable exit rather than a silent zero, so the damage would be
  # noisy -- but it would still take a `--update` to notice, and the whole point
  # of the ratchet is that it is checked on every pull request.
  cat > "$BASELINE_FILE" <<EOF
# Baselines for hack/patch-metric.sh. Lowered by --update as coupling is
# removed; never raised. See that script's header for what each number is and
# why it exists, and hack/hermes_touchpoints.py for the four below the rule.
BASELINE_APPLY_SETS=$apply_sets
BASELINE_VERIFY_SETS=$verify_sets
BASELINE_DOCKERFILE_PATCH_REFS=$dockerfile_patch_refs

# Counted by hack/hermes_touchpoints.py; run it with --list to see what each
# number matched.
BASELINE_DOCKERFILE_EDITS=$HERMES_TOUCHPOINT_DOCKERFILE_EDITS
BASELINE_SITECUSTOMIZE_TARGETS=$HERMES_TOUCHPOINT_SITECUSTOMIZE_TARGETS
BASELINE_INTERNAL_IMPORT_PLUGINS=$HERMES_TOUCHPOINT_INTERNAL_IMPORT_PLUGINS
BASELINE_DIRECT_TABLE_ACCESS=$HERMES_TOUCHPOINT_DIRECT_TABLE_ACCESS
EOF
  echo
  echo "✅ Baseline lowered. Commit $BASELINE_FILE with the change that earned it."
  exit 0
fi

# ------------------------------------------------------------------------------
# Exit status
# ------------------------------------------------------------------------------
# --summary-only is for the advisory CI job, which reports the number without
# turning a coupling regression into a red pull request. Locally the exit code
# is the useful part.
if [ "$SUMMARY_ONLY" -eq 1 ]; then
  exit 0
fi

if [ "$REGRESSED" -eq 1 ]; then
  echo
  echo "FAIL: Hermes coupling grew. A milestone that needs a new patch set is" >&2
  echo "      mis-designed - see implementation.md section 0.4/0.5." >&2
  exit 1
fi

if [ "$IMPROVED" -eq 1 ]; then
  echo
  echo "Coupling fell below the baseline. Run 'bash hack/patch-metric.sh --update'"
  echo "and commit the result so the ratchet holds."
fi

exit 0
