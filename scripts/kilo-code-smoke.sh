#!/usr/bin/env bash
# kilo-code-smoke.sh — v18716.1 operator-facing Kilo Code end-to-end smoke
#
# Drives the Go integration test (TestKiloCodeE2E_MiniMaxRoundTrip) and
# prints a clear PASS / FAIL / SKIP verdict. Exits 0 on PASS, 1 on FAIL,
# 2 on SKIP (so CI gates can distinguish "needs operator action" from
# "broken wire").
#
# Usage (operator):
#
#     OPENAI_BASE_URL=https://52.64.8.153/minimax/v1 \
#     OPENAI_API_KEY="<1Password HelixonSafe/MiniMax Token Plan key>" \
#       timeout 120 scripts/kilo-code-smoke.sh
#
# Usage (CI, all gates pre-wired via env):
#
#     export OPENAI_BASE_URL=...
#     export OPENAI_API_KEY=...
#     timeout 180 ./scripts/kilo-code-smoke.sh
#
# Required env:
#
#   OPENAI_BASE_URL  (default: https://52.64.8.153/minimax/v1)
#   OPENAI_API_KEY   (required; no default)
#
# Optional env:
#
#   KILO_CODE_BASE_URL  alias for OPENAI_BASE_URL (overrides default)
#   KILO_CODE_API_KEY   alias for OPENAI_API_KEY
#   KILO_CODE_MODEL     default "MiniMax-M3"; override for swap tests
#   HELIXCHANNEL_TLS_INSECURE_SKIP_VERIFY=1 to skip TLS verify (test rigs only)
#   REPO_DIR            override repo cwd (default: parent of this script)
#
# Anti-shell-leak (no-shell-leak.mdc Cat 4): the API key value is NEVER
# echoed. Only a redacted length and presence flag is printed.

set -u

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
BASE_URL="${KILO_CODE_BASE_URL:-${OPENAI_BASE_URL:-https://52.64.8.153/minimax/v1}}"
MODEL="${KILO_CODE_MODEL:-MiniMax-M3}"
API_KEY="${KILO_CODE_API_KEY:-${OPENAI_API_KEY:-}}"

if [ -z "$API_KEY" ]; then
  echo "SKIP: OPENAI_API_KEY (or KILO_CODE_API_KEY) not set — v18716.1 G2 SKIP per ADR-083 C4" >&2
  echo "Operator action: rotate 1Password item HelixonSafe/MiniMax Token Plan Key, then re-run with:" >&2
  echo "    OPENAI_API_KEY=\$(op read 'op://HelixonSafe/<uuid>/<field>' --out-file -f /tmp/.kilo && cat /tmp/.kilo && rm /tmp/.kilo) \\" >&2
  echo "      timeout 120 $0" >&2
  exit 2
fi

# Verify the repo has go.mod (sanity).
if [ ! -f "$REPO_DIR/go.mod" ]; then
  echo "FAIL: REPO_DIR ($REPO_DIR) does not contain go.mod" >&2
  exit 1
fi

# Sanity-check the base URL host is reachable on TCP/443 within 5s.
# This catches a stale nginx / Lightsail firewall rule before we burn
# the 30s request budget.
host="${BASE_URL#https://}"
host="${host#http://}"
host="${host%%/*}"
host="${host%%:*}"

if command -v timeout >/dev/null 2>&1; then
  if ! timeout 5 bash -c "</dev/tcp/$host/443" 2>/dev/null; then
    echo "FAIL: TCP/443 dial to $host failed within 5s" >&2
    echo "Operator action: run 'helixchannel endpoint-check --host $host' from cmd/helixchannel binary" >&2
    exit 1
  fi
fi

# Export the resolved values into env so the Go test sees them.
export KILO_CODE_BASE_URL="$BASE_URL"
export KILO_CODE_MODEL="$MODEL"
# API key already in env. Anti-shell-leak: we never echo it; we only
# note its presence to log.
key_len=${#API_KEY}
echo "v18716.1 Kilo Code E2E smoke"
echo "  base_url:   $BASE_URL"
echo "  model:      $MODEL"
echo "  api_key:    present (length=$key_len, redacted)"
echo "  repo:       $REPO_DIR"
echo ""

# Drive the integration test. -tags=realmodel enables the build-tag-gated
# test file. -v for verbose so the operator sees the t.Logf lines.
cd "$REPO_DIR" || {
  echo "FAIL: cd $REPO_DIR" >&2
  exit 1
}

out="$(timeout 180 go test -tags=realmodel -count=1 -v -run TestKiloCodeE2E ./internal/tunnel/integration/... 2>&1)"
rc=$?

# Print the captured output verbatim for operator inspection.
echo "$out"
echo ""

# Verdict logic. The Go test uses t.Skip on quota / network flakes;
# the smoke wrapper mirrors that.
if [ $rc -eq 0 ]; then
  if echo "$out" | grep -q "^--- PASS"; then
    echo "VERDICT: PASS — v18716.1 Kilo Code E2E round-trip succeeded."
    echo "Operator action: open VS Code → Kilo Code extension, set:"
    echo "    kilocode.openAiBaseUrl: $BASE_URL"
    echo "    kilocode.openAiApiKey:  <from 1Password HelixonSafe>"
    echo "    kilocode.openAiModel:   $MODEL"
    exit 0
  fi
  echo "VERDICT: UNKNOWN — go test exit 0 but no PASS line found." >&2
  exit 1
fi

if echo "$out" | grep -q "^--- SKIP"; then
  echo "VERDICT: SKIP — v18716.1 G2 gate tripped (see reasons above). Re-run after operator action." >&2
  exit 2
fi

echo "VERDICT: FAIL — v18716.1 Kilo Code E2E wire broken. See go test output above." >&2
exit 1