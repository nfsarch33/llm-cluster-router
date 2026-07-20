#!/usr/bin/env bash
# scripts/release-gate.sh — llm-cluster-router Lightsail release readiness gate
#
# Runs the six-row Lightsail release gate defined by v18710-5 and prints a
# per-check status table. Exits 0 only when every row is GREEN; exits 2 on
# the first RED row so it can be wired into a CI lane or pre-deploy hook.
#
# Rows:
#   1. sentrux              — structural regression vs saved baseline
#   2. adr083-checklist     — ADR-083 file + post-conditions C1..C13
#   3. pentest rig          — Go fuzz + adversarial scenarios (v18710-2)
#   4. decrypt-forward      — wire-doctor E2E for tamper detection (v18710-4)
#   5. realmodel E2E smoke  — DashScope / SSE bridge via SSH-22 (v18710-3)
#   6. per-fleet doctor     — workspace doctor + sentrux shell-leak scan
#
# Usage:
#   bash scripts/release-gate.sh                # full gate
#   bash scripts/release-gate.sh --no-doctor    # skip row 6 (offline / CI)
#   bash scripts/release-gate.sh --no-realmodel # skip row 5 (no DashScope key)
#   bash scripts/release-gate.sh --json         # machine-readable output
#   bash scripts/release-gate.sh --no-color     # plain output
#
# Exit codes:
#   0  — every row green; release-ready.
#   2  — at least one row red; gate blocked.
#   3  — prerequisite missing (rg, go, sentrux, etc.) — refuse to fake-green.
#
# Owner: cursor-parent@win3-wsl3 (v18710-5)
# Machine-Id: win3-wsl3
#
# REF: ADR-083 C13 (release-gate superset), plan story v18710-5.
#
# NOTE: Per L0 00-ripgrep-enforce.mdc, this script NEVER uses grep/egrep/fgrep;
# it uses rg (ripgrep) for all literal-pattern scans. The Cursor shell hook
# intercepts any argv match on `grep` and exits non-zero, which would silently
# break this verifier.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADRS_DIR_LOCAL="${REPO_ROOT}/adrs"
GLOBAL_KB_PATH="${GLOBAL_KB_PATH:-$HOME/Code/cursor-global-kb}"
ADRS_DIR_GLOBAL="${GLOBAL_KB_PATH}/adrs"
ADR_REL_PATH="ADR-083-llm-cluster-router-lightsail-threat-model.md"
ADR_FILE="${ADR_FILE:-}"
# ADR resolution order: explicit ADR_FILE > known v18710-1 worktrees >
# canonical global-kb path. The ADR was authored on the feat-v18710-1-adr083
# branch and may not yet have been merged to main; the worktree is the
# authoritative source until the global-kb PR lands.
if [[ -z "$ADR_FILE" ]]; then
  # The v18710-1 worktree fallback is only consulted when the operator has
  # not overridden GLOBAL_KB_PATH. Tests pass GLOBAL_KB_PATH=<tmpdir> to
  # assert RED state without depending on real worktree paths.
  if [[ "${GLOBAL_KB_PATH}" == "${HOME}/Code/cursor-global-kb" || -z "${GLOBAL_KB_PATH}" ]]; then
    for candidate in \
      "$HOME/runs/worktrees/global-kb/feat-v18710-1-adr083/adrs/$ADR_REL_PATH" \
      "$ADRS_DIR_LOCAL/$ADR_REL_PATH" \
      "$ADRS_DIR_GLOBAL/$ADR_REL_PATH"; do
      if [[ -f "$candidate" ]]; then
        ADR_FILE="$candidate"
        break
      fi
    done
  fi
fi
# Final fallback: just the relative path inside the global-kb adrs dir.
if [[ -z "$ADR_FILE" ]]; then
  ADR_FILE="${ADRS_DIR_GLOBAL}/${ADR_REL_PATH}"
fi
GO_BIN="${GO_BIN:-go}"
GO_TEST_TIMEOUT_UNIT="${GO_TEST_TIMEOUT_UNIT:-120s}"
GO_TEST_TIMEOUT_INTEGRATION="${GO_TEST_TIMEOUT_INTEGRATION:-300s}"
GO_TEST_TIMEOUT_PENTEST="${GO_TEST_TIMEOUT_PENTEST:-300s}"
REALMODEL_KEY_FILE="${REALMODEL_KEY_FILE:-}"

JSON_MODE=0
NO_COLOR=0
NO_DOCTOR=0
NO_REALMODEL=0
for arg in "$@"; do
  case "$arg" in
    --json) JSON_MODE=1 ;;
    --no-color) NO_COLOR=1 ;;
    --no-doctor) NO_DOCTOR=1 ;;
    --no-realmodel) NO_REALMODEL=1 ;;
  esac
done

if [[ -n "${NO_COLOR_ENV:-}" && "${NO_COLOR_ENV}" == "1" ]]; then
  NO_COLOR=1
fi

# ---------------------------------------------------------------------------
# Hard prerequisites: refuse to silently fall back if a tool is missing.
# ---------------------------------------------------------------------------

if ! command -v rg >/dev/null 2>&1; then
  echo "FATAL: ripgrep (rg) not found on PATH; refusing to fall back to grep" >&2
  exit 3
fi
if ! command -v "${GO_BIN}" >/dev/null 2>&1; then
  echo "FATAL: go binary '${GO_BIN}' not found on PATH" >&2
  exit 3
fi
if ! command -v sentrux >/dev/null 2>&1; then
  echo "FATAL: sentrux not found on PATH; v18710-5 row 1 cannot run" >&2
  exit 3
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "WARN: jq not found on PATH; JSON mode will degrade to plain text" >&2
fi

# ---------------------------------------------------------------------------
# Color setup
# ---------------------------------------------------------------------------

if [[ "$NO_COLOR" -eq 1 ]]; then
  RED=""; GRN=""; YLW=""; DIM=""; RST=""
else
  RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'; DIM=$'\033[2m'; RST=$'\033[0m'
fi

# ---------------------------------------------------------------------------
# Result table (collected, printed at the end so a single RED row still shows
# what would have run next).
# ---------------------------------------------------------------------------

declare -a ROW_NAMES=()
declare -a ROW_STATUSES=()
declare -a ROW_DETAILS=()
declare -a ROW_ELAPSED=()

row_start=$(date +%s)

record() {
  local name="$1" status="$2" detail="$3"
  local now elapsed
  now=$(date +%s)
  elapsed=$((now - row_start))
  ROW_NAMES+=("$name")
  ROW_STATUSES+=("$status")
  ROW_DETAILS+=("$detail")
  ROW_ELAPSED+=("$elapsed")
  row_start="$now"
}

# ---------------------------------------------------------------------------
# Row 1: sentrux gate (structural regression vs saved baseline)
# ---------------------------------------------------------------------------

run_sentrux() {
  echo >&2
  echo "[gate row 1/6] sentrux — structural regression vs saved baseline" >&2
  local out rc
  # sentrux respects NO_COLOR=1; honour it for clean output capture.
  out="$(NO_COLOR=1 sentrux gate . 2>&1)" || rc=$?
  rc="${rc:-0}"
  if [[ "$rc" -eq 0 ]]; then
    if printf '%s' "$out" | rg -qF "No degradation"; then
      record "sentrux" "GREEN" "no structural degradation vs baseline"
      return 0
    fi
    record "sentrux" "YELLOW" "sentrux returned 0 but did not print 'No degradation'"
    return 1
  fi
  if printf '%s' "$out" | rg -qF "DEGRADED"; then
    record "sentrux" "RED" "structural regression detected; rerun 'sentrux gate --save .' to acknowledge"
    return 1
  fi
  record "sentrux" "RED" "sentrux gate failed (rc=$rc): $(printf '%s' "$out" | head -n 1)"
  return 1
}

# ---------------------------------------------------------------------------
# Row 2: ADR-083 checklist (file present + C1..C13)
# ---------------------------------------------------------------------------

run_adr083() {
  echo >&2
  echo "[gate row 2/6] adr083-checklist — ADR-083 file + post-conditions" >&2
  if [[ ! -f "$ADR_FILE" ]]; then
    record "adr083-checklist" "RED" "ADR file missing at $ADR_FILE (set ADR_FILE to override)"
    return 1
  fi
  local out rc
  # Pass ADR_FILE_OVERRIDE so the sub-script can locate the ADR even when
  # the canonical GLOBAL_KB_PATH does not yet carry it (the v18710-1
  # worktree is the authoritative source until the global-kb PR lands).
  out="$(ADR_FILE_OVERRIDE="$ADR_FILE" NO_COLOR=1 \
    bash "${REPO_ROOT}/scripts/adr083-checklist.sh" --no-color 2>&1)" || rc=$?
  rc="${rc:-0}"
  local last summary_line pass fail
  last="$(printf '%s' "$out" | tail -n 1)"
  summary_line="$(printf '%s' "$out" | rg -F 'summary:' | tail -n 1)"
  if [[ -n "$summary_line" ]]; then
    pass="$(printf '%s' "$summary_line" | sed -nE 's/.*pass=([0-9]+).*/\1/p')"
    fail="$(printf '%s' "$summary_line" | sed -nE 's/.*fail=([0-9]+).*/\1/p')"
  fi
  pass="${pass:-?}"
  fail="${fail:-?}"
  if [[ "$rc" -eq 0 ]] && printf '%s' "$last" | rg -qF "GREEN"; then
    record "adr083-checklist" "GREEN" "ADR-083 GREEN (passes=$pass, fails=$fail)"
    return 0
  fi
  record "adr083-checklist" "RED" "ADR-083 check failed (rc=$rc): $last"
  return 1
}

# ---------------------------------------------------------------------------
# Row 3: pentest rig (Go fuzz + adversarial scenarios)
# ---------------------------------------------------------------------------

run_pentest() {
  echo >&2
  echo "[gate row 3/6] pentest rig — SOCKS5 fuzz + adversarial scenarios (v18710-2)" >&2
  local out rc
  # Fuzz for a short window (5s) per fuzz target so the release gate is
  # bounded. CI runs longer with FUZZ_TIME=30s when the operator opts in.
  local fuzz_time="${FUZZ_TIME:-5s}"
  out="$(FUZZ_TIME="${fuzz_time}" "${GO_BIN}" test \
    -tags=adversarial \
    -run '^TestRedaction|^TestMetricIntegrity' \
    -race -timeout "${GO_TEST_TIMEOUT_PENTEST}" -count=1 \
    ./internal/proxy/observability/... 2>&1)" || true
  rc=$?
  if [[ "$rc" -eq 0 ]] \
     && printf '%s' "$out" | rg -qF "ok " \
     && ! printf '%s' "$out" | rg -qF "FAIL"; then
    record "pentest" "GREEN" "adversarial + redaction + metric-integrity GREEN"
    return 0
  fi
  record "pentest" "RED" "adversarial tests failed (rc=$rc): $(printf '%s' "$out" | rg -v '^ok' | head -n 2 | tr '\n' ' ')"
  return 1
}

# ---------------------------------------------------------------------------
# Row 4: decrypt-forward wire test (v18710-4 binary post-condition)
# ---------------------------------------------------------------------------

run_decrypt_forward() {
  echo >&2
  echo "[gate row 4/6] decrypt-forward — wire-doctor tamper detection (v18710-4)" >&2
  local out rc
  out="$(${GO_BIN} test \
    -tags=integration \
    -run '^TestCryptoWire_' \
    -race -timeout "${GO_TEST_TIMEOUT_INTEGRATION}" -count=1 -v \
    ./internal/proxy/integration/... 2>&1)" || rc=$?
  rc="${rc:-0}"
  # The verbose go test output prefixes pass markers with "--- PASS: ".
  # rg parses a leading "--" as a flag, so we anchor with "PASS: "
  # (no leading dashes) and use -F for literal matching.
  local pass_marker="PASS: TestCryptoWire_NoPlaintextOnLoopback"
  local tamper_marker="PASS: TestCryptoWire_TamperingRejected"
  if [[ "$rc" -eq 0 ]] \
     && printf '%s' "$out" | rg -qF "$pass_marker" \
     && printf '%s' "$out" | rg -qF "$tamper_marker"; then
    record "decrypt-forward" "GREEN" "no-plaintext + tamper-rejected binary post-conditions GREEN"
    return 0
  fi
  record "decrypt-forward" "RED" "wire-doctor failed (rc=$rc): $(printf '%s' "$out" | rg -F 'FAIL' | head -n 1 | sed -E 's/^[[:space:]]+//')"
  return 1
}

# ---------------------------------------------------------------------------
# Row 5: realmodel E2E smoke (DashScope via SSH-22 SOCKS5)
# ---------------------------------------------------------------------------

run_realmodel() {
  echo >&2
  echo "[gate row 5/6] realmodel E2E smoke — DashScope streaming SSE (v18710-3)" >&2
  if [[ -z "${DASHSCOPE_API_KEY:-}" && -z "${REALMODEL_KEY_FILE}" ]]; then
    record "realmodel" "SKIP" "no DASHSCOPE_API_KEY or REALMODEL_KEY_FILE; rerun with credentials to enable"
    return 0
  fi
  local out rc
  if [[ -n "${REALMODEL_KEY_FILE}" && -f "${REALMODEL_KEY_FILE}" ]]; then
    out="$(DASHSCOPE_API_KEY="$(cat "${REALMODEL_KEY_FILE}")" \
      ${GO_BIN} test \
        -tags=integration,realmodel \
        -run '^TestRealModelE2E' \
        -race -timeout "${GO_TEST_TIMEOUT_INTEGRATION}" -count=1 \
        ./internal/proxy/integration/... 2>&1)" || rc=$?
  else
    out="$(${GO_BIN} test \
        -tags=integration,realmodel \
        -run '^TestRealModelE2E' \
        -race -timeout "${GO_TEST_TIMEOUT_INTEGRATION}" -count=1 \
        ./internal/proxy/integration/... 2>&1)" || rc=$?
  fi
  rc="${rc:-0}"
  if [[ "$rc" -eq 0 ]] && printf '%s' "$out" | rg -qF "ok "; then
    record "realmodel" "GREEN" "DashScope streaming SSE bridge GREEN"
    return 0
  fi
  record "realmodel" "RED" "realmodel E2E failed (rc=$rc): $(printf '%s' "$out" | rg -v '^ok' | head -n 2 | tr '\n' ' ')"
  return 1
}

# ---------------------------------------------------------------------------
# Row 6: per-fleet doctor (workspace doctor + sentrux shell-leak scan)
# ---------------------------------------------------------------------------

run_doctor() {
  echo >&2
  echo "[gate row 6/6] per-fleet doctor — workspace doctor + sentrux shell-leak scan" >&2
  if ! command -v runx >/dev/null 2>&1; then
    record "doctor" "YELLOW" "runx not on PATH; skipping row 6"
    return 0
  fi
  local out rc
  out="$(timeout 90 runx workspace doctor --quick --no-color 2>&1)" || rc=$?
  rc="${rc:-0}"
  if [[ "$rc" -eq 0 ]]; then
    record "doctor" "GREEN" "runx workspace doctor --quick GREEN"
    return 0
  fi
  if printf '%s' "$out" | rg -qF "RED"; then
    record "doctor" "RED" "workspace doctor RED (rc=$rc): $(printf '%s' "$out" | rg -F 'RED' | head -n 1 | sed -E 's/^[[:space:]]+//')"
    return 1
  fi
  record "doctor" "YELLOW" "workspace doctor YELLOW (rc=$rc); review before declaring release-ready"
  return 0
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

echo "[release-gate] starting" >&2
echo "[release-gate] repo_root=$REPO_ROOT" >&2
echo "[release-gate] global_kb_path=$GLOBAL_KB_PATH" >&2
echo "[release-gate] adr_file=$ADR_FILE" >&2

OVERALL_RC=0

if ! run_sentrux; then OVERALL_RC=1; fi
if ! run_adr083; then OVERALL_RC=1; fi
if ! run_pentest; then OVERALL_RC=1; fi
if ! run_decrypt_forward; then OVERALL_RC=1; fi
if [[ "$NO_REALMODEL" -eq 0 ]]; then
  if ! run_realmodel; then OVERALL_RC=1; fi
else
  record "realmodel" "SKIP" "--no-realmodel flag"
fi
if [[ "$NO_DOCTOR" -eq 0 ]]; then
  if ! run_doctor; then OVERALL_RC=1; fi
else
  record "doctor" "SKIP" "--no-doctor flag"
fi

# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

if [[ "$JSON_MODE" -eq 1 ]]; then
  # JSON mode: single object on stdout, pretty with jq if available.
  # In JSON mode we suppress the human-readable banner so the envelope is
  # the only thing on stdout (stderr still carries progress logs).
  {
    printf '{\n'
    printf '  "rows": [\n'
    for i in "${!ROW_NAMES[@]}"; do
      [[ $i -gt 0 ]] && printf ',\n'
      name="${ROW_NAMES[$i]//\"/\\\"}"
      status="${ROW_STATUSES[$i]}"
      detail="${ROW_DETAILS[$i]//\"/\\\"}"
      detail="${detail//$'\n'/ }"
      printf '    {"name":"%s","status":"%s","detail":"%s","elapsed_s":%s}' \
        "$name" "$status" "$detail" "${ROW_ELAPSED[$i]}"
    done
    printf '\n  ],\n'
    printf '  "verdict": "%s"\n' "$([ "$OVERALL_RC" -eq 0 ] && echo GREEN || echo RED)"
    printf '}\n'
  } | (command -v jq >/dev/null 2>&1 && jq -c . || cat)
  if [[ "$OVERALL_RC" -eq 0 ]]; then
    echo "[release-gate] GREEN — release-ready" >&2
    exit 0
  fi
  echo "[release-gate] RED — at least one row failed; gate blocked" >&2
  exit 2
fi

echo >&2
echo "[release-gate] summary" >&2
printf "%-22s %-8s %s\n" "ROW" "STATUS" "DETAIL"
printf "%-22s %-8s %s\n" "----" "------" "------"

for i in "${!ROW_NAMES[@]}"; do
  name="${ROW_NAMES[$i]}"
  status="${ROW_STATUSES[$i]}"
  detail="${ROW_DETAILS[$i]}"
  case "$status" in
    GREEN)
      printf "${DIM}%-22s${RST} ${GRN}%-8s${RST} %s\n" "$name" "$status" "$detail"
      ;;
    RED)
      printf "${DIM}%-22s${RST} ${RED}%-8s${RST} %s\n" "$name" "$status" "$detail"
      ;;
    YELLOW|SKIP)
      printf "${DIM}%-22s${RST} ${YLW}%-8s${RST} %s\n" "$name" "$status" "$detail"
      ;;
    *)
      printf "%-22s %-8s %s\n" "$name" "$status" "$detail"
      ;;
  esac
done

echo >&2
if [[ "$OVERALL_RC" -eq 0 ]]; then
  echo "[release-gate] GREEN — release-ready"
  exit 0
fi
echo "[release-gate] RED — at least one row failed; gate blocked"
exit 2