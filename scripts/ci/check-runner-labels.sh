#!/usr/bin/env bash
# check-runner-labels.sh - a public repository runs CI on standard
# GitHub-hosted runners only.
#
# A self-hosted runner on a public repository executes whatever a pull request
# from a fork puts in a workflow, on the runner's own machine. Larger hosted
# runners are billed even for public repositories. So every `runs-on:` in
# .github/workflows must be exactly one of the labels below. Anything else
# fails: a self-hosted list, a larger-runner label, an expression, or a value
# this script cannot read on one line.
#
# Workflows that cannot run on a hosted runner are named, one file name per
# line, in .github/runner-label-exceptions.txt. They are skipped and printed,
# so an exception is always visible in the job log.
#
# Usage: check-runner-labels.sh [workflow-dir]      default .github/workflows
#        check-runner-labels.sh --self-test
set -euo pipefail

ALLOWED="ubuntu-latest ubuntu-24.04 ubuntu-22.04"

check() { # dir exceptions-file -> 0 clean, 1 findings
  local dir="$1" exc="$2" bad=0 seen=0 f n text val a ok
  while IFS=: read -r f n text; do
    if [ -f "$exc" ] && grep -qxF -- "$(basename "$f")" "$exc"; then
      echo "EXCEPTION $(basename "$f"):$n (listed in $(basename "$exc"))"; continue
    fi
    seen=$((seen+1))
    val=$(printf '%s' "$text" | sed -E 's/^[[:space:]]*runs-on:[[:space:]]*//; s/[[:space:]]*#.*$//; s/[[:space:]]+$//')
    val=${val#[\"\']}; val=${val%[\"\']}
    ok=0; for a in $ALLOWED; do [ "$val" = "$a" ] && ok=1; done
    if [ "$ok" = 0 ]; then echo "FAIL $f:$n: runs-on '${val}' is not a standard GitHub-hosted label ($ALLOWED)"; bad=1; fi
  done < <(grep -rnE '^[[:space:]]*runs-on:' "$dir" --include='*.yml' --include='*.yaml' || true)
  if [ "$seen" = 0 ] && [ "$bad" = 0 ]; then echo "FAIL no runs-on line was checked under $dir: nothing to judge is not a pass"; return 1; fi
  [ "$bad" = 0 ] || return 1
  echo "runner labels ok: $seen checked"
}

self_test() {
  local t pass=0 fail=0 rc; t=$(mktemp -d)
  row() { # name expected-rc file-content
    mkdir -p "$t/$1"; printf '%b' "$3" > "$t/$1/w.yml"
    rc=0; check "$t/$1" "$t/none" >/dev/null 2>&1 || rc=$?
    if [ "$rc" = "$2" ]; then pass=$((pass+1)); echo "  [PASS] $1"; else fail=$((fail+1)); echo "  [FAIL] $1 (rc $rc, expected $2)"; fi
  }
  row hosted-latest 0 'jobs:\n  a:\n    runs-on: ubuntu-latest\n'
  row hosted-pinned-with-comment 0 'jobs:\n  a:\n    runs-on: ubuntu-24.04  # pinned\n'
  row self-hosted-inline-list 1 'jobs:\n  a:\n    runs-on: [self-hosted, linux]\n'
  row self-hosted-block-list 1 'jobs:\n  a:\n    runs-on:\n      - self-hosted\n'
  row larger-runner 1 'jobs:\n  a:\n    runs-on: ubuntu-latest-8-cores\n'
  row expression 1 'jobs:\n  a:\n    runs-on: ${{ matrix.os }}\n'
  row one-bad-among-good 1 'jobs:\n  a:\n    runs-on: ubuntu-latest\n  b:\n    runs-on: self-hosted\n'
  row no-runs-on-at-all 1 'name: empty\n'
  mkdir -p "$t/exc"; printf 'jobs:\n  a:\n    runs-on: [self-hosted, linux]\n' > "$t/exc/local.yml"; printf 'jobs:\n  a:\n    runs-on: ubuntu-latest\n' > "$t/exc/ci.yml"; echo local.yml > "$t/exc.txt"
  rc=0; check "$t/exc" "$t/exc.txt" >/dev/null 2>&1 || rc=$?
  if [ "$rc" = 0 ]; then pass=$((pass+1)); echo "  [PASS] a listed exception is skipped"; else fail=$((fail+1)); echo "  [FAIL] a listed exception is skipped"; fi
  rc=0; check "$t/exc" "$t/none" >/dev/null 2>&1 || rc=$?
  if [ "$rc" = 1 ]; then pass=$((pass+1)); echo "  [PASS] the same file fails when it is not listed"; else fail=$((fail+1)); echo "  [FAIL] the same file fails when it is not listed"; fi
  rm -rf "$t"; echo "PASS: $pass, FAIL: $fail"; [ "$fail" = 0 ]
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
check "${1:-.github/workflows}" "${RUNNER_LABEL_EXCEPTIONS:-.github/runner-label-exceptions.txt}"
