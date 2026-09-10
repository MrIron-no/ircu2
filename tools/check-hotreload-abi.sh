#!/bin/sh
# check-hotreload-abi.sh - guard the hot-reload dump's raw bit/enum ABI.
#
# The hot-reload state dump (ircd/hotreload_dump.c) stores several fields as
# raw bit/enum values that are read back by a freshly execv()'d binary
# (ircd/hotreload_load.c).  Those numeric values MUST stay identical across an
# upgraded binary, or an old dump silently decodes into the wrong flags on the
# new image - a corruption with no error and no crash.
#
# This script builds ircd/test/hotreload_abi_gen (the authoritative generator,
# which prints the COMPILED values), runs it, and compares its output against
# the committed golden snapshot ircd/test/hotreload_abi.golden with APPEND-SAFE
# semantics:
#   - FAIL if a symbol in the golden file is MISSING or has a CHANGED value.
#   - OK   if the current output adds a brand-new symbol not in the golden file
#          (a note is printed reminding the developer to refresh the golden).
#
# Usage:
#   tools/check-hotreload-abi.sh            # check; exit non-zero on drift
#   tools/check-hotreload-abi.sh --update   # regenerate the golden snapshot
#
# Assumes a configured build tree (./configure has been run).  Robust to being
# run from anywhere; it locates the repo root relative to its own path.

set -eu

# Resolve the repo root from this script's location (tools/<script>).
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

gen_src="$repo_root/ircd/test/hotreload_abi_gen.c"
gen_bin="$repo_root/ircd/test/hotreload_abi_gen"
golden="$repo_root/ircd/test/hotreload_abi.golden"

update=0
if [ "${1:-}" = "--update" ]; then
  update=1
elif [ "${1:-}" != "" ]; then
  echo "usage: $0 [--update]" >&2
  exit 2
fi

if [ ! -f "$gen_src" ]; then
  echo "check-hotreload-abi: generator source not found: $gen_src" >&2
  exit 2
fi

# Build the generator.  Prefer the configured build rule so it matches the
# tree's flags; fall back to a direct compile if make is unavailable.
build_ok=0
if command -v make >/dev/null 2>&1 && [ -f "$repo_root/ircd/test/Makefile" ]; then
  if make -C "$repo_root/ircd/test" hotreload_abi_gen >/dev/null 2>&1; then
    build_ok=1
  fi
fi
if [ "$build_ok" -ne 1 ]; then
  cc="${CC:-cc}"
  if ! $cc -I"$repo_root/include" -I"$repo_root" -DIRCU2_BUILD -g -Wall \
       -o "$gen_bin" "$gen_src"; then
    echo "check-hotreload-abi: failed to build the ABI generator." >&2
    echo "  Is the tree configured?  Run ./configure first." >&2
    exit 2
  fi
fi

current=$(mktemp)
trap 'rm -f "$current"' EXIT
"$gen_bin" > "$current"

if [ "$update" -eq 1 ]; then
  cp "$current" "$golden"
  echo "check-hotreload-abi: refreshed golden snapshot ($(wc -l < "$golden" | tr -d ' ') symbols): $golden"
  exit 0
fi

if [ ! -f "$golden" ]; then
  echo "check-hotreload-abi: golden snapshot not found: $golden" >&2
  echo "  Generate it with: $0 --update" >&2
  exit 2
fi

# Compare golden vs current with append-safe semantics.  For each symbol in the
# golden file, require the same value in the current output.  New symbols in the
# current output that are absent from the golden are allowed (noted only).
status=0

# awk does the set comparison in one pass.  golden lines are "SYM VALUE".
report=$(awk '
  NR==FNR { gold[$1]=$2; goldseen[$1]=1; next }
  { cur[$1]=$2; curseen[$1]=1 }
  END {
    for (s in gold) {
      if (!(s in cur)) {
        printf "REMOVED %s %s\n", s, gold[s]
      } else if (cur[s] != gold[s]) {
        printf "CHANGED %s %s %s\n", s, gold[s], cur[s]
      }
    }
    for (s in cur) {
      if (!(s in gold))
        printf "NEW %s %s\n", s, cur[s]
    }
  }
' "$golden" "$current")

# Emit failures first, then notes.
fails=$(printf '%s\n' "$report" | grep -E '^(REMOVED|CHANGED) ' || true)
news=$(printf '%s\n' "$report" | grep -E '^NEW ' || true)

if [ -n "$fails" ]; then
  echo "$fails" | while read -r kind sym old new; do
    if [ "$kind" = "CHANGED" ]; then
      echo "Hot-reload dump ABI changed: $sym $old->$new. A reordered/renumbered bit or enum silently corrupts a hot RELOAD across an upgraded binary. If this change is intentional, bump the HOTRELOAD dump version in ircd/hotreload_dump.c and add loader compatibility handling in ircd/hotreload_load.c, then regenerate ircd/test/hotreload_abi.golden (tools/check-hotreload-abi.sh --update)." >&2
    else
      echo "Hot-reload dump ABI changed: $sym $old->(removed). A reordered/renumbered bit or enum silently corrupts a hot RELOAD across an upgraded binary. If this change is intentional, bump the HOTRELOAD dump version in ircd/hotreload_dump.c and add loader compatibility handling in ircd/hotreload_load.c, then regenerate ircd/test/hotreload_abi.golden (tools/check-hotreload-abi.sh --update)." >&2
    fi
  done
  status=1
fi

if [ -n "$news" ]; then
  echo "$news" | while read -r kind sym val; do
    echo "check-hotreload-abi: note: new guarded symbol '$sym' ($val) is not in the golden snapshot; refresh it with tools/check-hotreload-abi.sh --update."
  done
fi

if [ "$status" -eq 0 ]; then
  echo "check-hotreload-abi: OK ($(wc -l < "$golden" | tr -d ' ') guarded symbols unchanged)."
fi

exit $status
