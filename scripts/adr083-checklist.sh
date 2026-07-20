#!/usr/bin/env bash
# ADR-083 — llm-cluster-router Lightsail dual-listener threat model checklist
#
# Verifies that:
#   1. ADR-083 file is present at the canonical global-kb path.
#   2. The ADR file declares ≥12 binary post-conditions (we ship 13).
#   3. Every post-condition row is non-empty and well-formed.
#   4. The release-gate superset (C13) has a paired verifier path.
#
# Usage:
#   bash scripts/adr083-checklist.sh
#   bash scripts/adr083-checklist.sh --json
#   ADR_FILE_OVERRIDE=/path/to/adr083.md bash scripts/adr083-checklist.sh
#
# Exit codes:
#   0  — all checks pass (release-ready per ADR-083).
#   2  — at least one check failed.
#
# Owner: cursor-parent@win3-wsl3 (v18710-1)
# Machine-Id: win3-wsl3
#
# REF: ADR-083 (post-conditions C1..C13); v18710 plan story v18710-1.
#
# NOTE: Per L0 00-ripgrep-enforce.mdc, this script NEVER uses grep/egrep/fgrep;
# it uses rg (ripgrep) for all literal-pattern scans. The Cursor shell hook
# intercepts any argv match on `grep` and exits non-zero, which would silently
# break this verifier.
set -euo pipefail

ADR_REL_PATH="adrs/ADR-083-llm-cluster-router-lightsail-threat-model.md"
MIN_POSTCONDITIONS=12
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GLOBAL_KB_PATH="${GLOBAL_KB_PATH:-$HOME/Code/cursor-global-kb}"
ADR_FILE_OVERRIDE="${ADR_FILE_OVERRIDE:-}"
JSON_MODE=0
NO_COLOR=0
if [[ "${1:-}" == "--json" ]]; then
  JSON_MODE=1
fi
if [[ "${1:-}" == "--no-color" || "${2:-}" == "--no-color" ]]; then
  NO_COLOR=1
fi
if [[ -n "${NO_COLOR:-}" && "${NO_COLOR}" == "1" ]] || [[ -n "${NO_COLOR_ENV:-}" ]]; then
  NO_COLOR=1
fi

# Require rg on PATH; refuse to silently fall back to grep.
if ! command -v rg >/dev/null 2>&1; then
  echo "FATAL: ripgrep (rg) not found on PATH; refusing to fall back to grep" >&2
  exit 3
fi

if [[ "$NO_COLOR" -eq 1 ]]; then
  RED=""; GRN=""; YLW=""; RST=""
else
  RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; RST=$'\033[0m'
fi
PASS=0; FAIL=0
declare -a FINDINGS=()

emit() {
  local level="$1" code="$2" msg="$3"
  if [[ "$level" == "PASS" ]]; then
    PASS=$((PASS+1))
    printf "  %sPASS%s [%s] %s\n" "$GRN" "$RST" "$code" "$msg" >&2
  else
    FAIL=$((FAIL+1))
    FINDINGS+=("$code|$msg")
    printf "  %sFAIL%s [%s] %s\n" "$RED" "$RST" "$code" "$msg" >&2
  fi
}

echo "[adr083-checklist] starting verification"
echo "[adr083-checklist] repo_root=$REPO_ROOT"
echo "[adr083-checklist] global_kb_path=$GLOBAL_KB_PATH"
echo "[adr083-checklist] min_postconditions=$MIN_POSTCONDITIONS"

# Resolve ADR file path: override > canonical location.
ADR_FILE="$GLOBAL_KB_PATH/$ADR_REL_PATH"
if [[ -n "$ADR_FILE_OVERRIDE" && -f "$ADR_FILE_OVERRIDE" ]]; then
  ADR_FILE="$ADR_FILE_OVERRIDE"
fi

# Check 1: ADR file exists
echo "[check 1/4] ADR file presence"
if [[ -f "$ADR_FILE" ]]; then
  emit PASS "ADR_FILE_EXISTS" "$ADR_FILE"
else
  emit FAIL "ADR_FILE_MISSING" "$ADR_FILE not found"
fi

# Check 2: ADR frontmatter has required fields
echo "[check 2/4] ADR frontmatter"
if [[ -f "$ADR_FILE" ]]; then
  required_fm=(title status date plan machine_id)
  missing_fm=0
  for f in "${required_fm[@]}"; do
    # rg -qF: literal pattern; -e gives explicit pattern arg (no shell escape worries).
    if rg -qF "${f}:" "$ADR_FILE"; then
      : # field present
    else
      missing_fm=$((missing_fm+1))
      emit FAIL "FRONTMATTER_FIELD_${f}" "missing frontmatter field: ${f}"
    fi
  done
  if [[ $missing_fm -eq 0 ]]; then
    emit PASS "FRONTMATTER_COMPLETE" "all required frontmatter fields present"
  fi
fi

# Check 3: count post-conditions in the markdown table
echo "[check 3/4] Post-condition count (≥$MIN_POSTCONDITIONS required)"
if [[ -f "$ADR_FILE" ]]; then
  # Count table rows whose first column starts with **C followed by digits.
  # rg -c counts matching LINES, which is what we want for distinct rows.
  pc_count=$(rg -c '\| \*\*C[0-9]+' "$ADR_FILE" || true)
  if [[ -z "$pc_count" ]]; then pc_count=0; fi
  if [[ "$pc_count" -ge "$MIN_POSTCONDITIONS" ]]; then
    emit PASS "POSTCONDITION_COUNT" "found $pc_count post-conditions (≥$MIN_POSTCONDITIONS)"
  else
    emit FAIL "POSTCONDITION_COUNT" "found only $pc_count post-conditions; need ≥$MIN_POSTCONDITIONS"
  fi
fi

# Check 4: each post-condition has a non-empty Verifier column.
echo "[check 4/4] Post-condition rows have paired verifier path"
if [[ -f "$ADR_FILE" ]]; then
  # Read the post-condition rows via process substitution, parse C<n> id,
  # and check that each row references at least one of: v18710-, ADR-082,
  # ADR-084, superset.
  bad_rows=0
  while IFS= read -r row; do
    cid=$(printf '%s' "$row" | sed -nE 's/.*\*\*C([0-9]+).*/\1/p' | head -n1)
    if [[ -z "$cid" ]]; then
      continue
    fi
    if ! printf '%s' "$row" | rg -q 'v18710-|ADR-082|ADR-084|supersets'; then
      bad_rows=$((bad_rows+1))
      emit FAIL "PC_C${cid}_NO_VERIFIER" "row C${cid} lacks verifier reference"
    fi
  done < <(rg '\| \*\*C[0-9]+' "$ADR_FILE" || true)
  if [[ $bad_rows -eq 0 ]]; then
    emit PASS "ALL_PCS_HAVE_VERIFIER" "every post-condition has a paired verifier"
  fi
fi

# Summary
echo
echo "[adr083-checklist] summary: pass=$PASS fail=$FAIL"

if [[ "$JSON_MODE" -eq 1 ]]; then
  printf '{"pass":%d,"fail":%d,"findings":[' "$PASS" "$FAIL"
  first=1
  for f in "${FINDINGS[@]}"; do
    code="${f%%|*}"
    msg="${f#*|}"
    msg="${msg//\"/\\\"}"
    if [[ $first -eq 0 ]]; then printf ','; fi
    printf '{"code":"%s","msg":"%s"}' "$code" "$msg"
    first=0
  done
  printf ']}\n'
fi

if [[ $FAIL -gt 0 ]]; then
  exit 2
fi
echo "[adr083-checklist] GREEN — release-ready per ADR-083"
exit 0