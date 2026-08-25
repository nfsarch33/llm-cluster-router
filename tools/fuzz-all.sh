#!/usr/bin/env bash
# tools/fuzz-all.sh -- run every fuzz target in the repository, once, under a
# bounded time budget.
#
# `go test -fuzz` drives exactly one target in exactly one package per
# invocation, so the set has to be enumerated. Enumerating it -- rather than
# listing targets by hand in the Makefile -- is the whole point: a new FuzzXxx
# is enrolled the moment it is written, and a tagged tier that has stopped
# compiling fails here loudly instead of rotting silently.
#
# Usage:  tools/fuzz-all.sh [fuzztime]
# Env:    FUZZTIME (default 30s), GO (default `go`)
#
# Exit codes: 0 = every target survived its budget. 1 = at least one crasher
# (the reproducer is written under <pkg>/testdata/fuzz/<Target>/ -- commit it,
# it is now a regression test), or the enumeration itself found nothing, which
# means this script is broken rather than the code being clean.
set -uo pipefail

GO="${GO:-go}"
FUZZTIME="${1:-${FUZZTIME:-30s}}"

# Tag sets to enumerate. "" is the default build. The others are tiers whose
# fuzz targets are invisible without their tag and would otherwise never run.
# Keep in sync with BUILD_TAGS in the Makefile.
TAGSETS=("" "adversarial" "realmodel")

declare -A seen=()
rc=0
count=0

for tags in "${TAGSETS[@]}"; do
  tagflag=()
  label="default-build"
  if [ -n "$tags" ]; then
    tagflag=(-tags="$tags")
    label="tags=$tags"
  fi

  # Cheap prefilter: only ask `go test -list` (which builds a test binary) about
  # packages whose sources actually mention a fuzz target.
  if ! pkginfo=$("$GO" list "${tagflag[@]}" -f '{{.Dir}}|{{.ImportPath}}' ./... 2>/dev/null); then
    echo "fuzz-all: go list failed for $label" >&2
    exit 1
  fi

  while IFS='|' read -r dir pkg; do
    [ -n "$dir" ] || continue
    grep -lE '^func Fuzz' "$dir"/*_test.go >/dev/null 2>&1 || continue

    targets=$("$GO" test "${tagflag[@]}" -list='^Fuzz' "$pkg" 2>/dev/null |
      sed -n 's/^\(Fuzz[A-Za-z0-9_]*\)$/\1/p')

    for t in $targets; do
      key="$pkg|$t"
      if [ -n "${seen[$key]:-}" ]; then
        continue
      fi
      seen["$key"]=1
      count=$((count + 1))
      echo "==> $t  $pkg  [$label]  -fuzztime=$FUZZTIME"
      if ! "$GO" test "${tagflag[@]}" -run='^$' -fuzz="^${t}\$" -fuzztime="$FUZZTIME" "$pkg"; then
        rc=1
        echo "FUZZ FAIL: $t ($pkg, $label) -- reproducer under $dir/testdata/fuzz/$t/" >&2
      fi
    done
  done <<<"$pkginfo"
done

if [ "$count" -eq 0 ]; then
  echo "fuzz-all: enumerated ZERO fuzz targets. That is an enumeration bug, not a clean repo." >&2
  exit 1
fi

if [ "$rc" -eq 0 ]; then
  echo "fuzz-all: $count target(s), $FUZZTIME each, no crashers."
else
  echo "fuzz-all: $count target(s) run; at least one crasher (see above)." >&2
fi
exit "$rc"
