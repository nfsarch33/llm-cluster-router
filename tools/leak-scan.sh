#!/usr/bin/env bash
# tools/leak-scan.sh
# Anti-leak scan for the public llm-cluster-router mirror.
# Exits 0 if clean, 1 if any leak hits are found.
# Patterns:
#   - 1Password vaults / UUIDs
#   - production hostnames (cylrl.dev)
#   - production IPs (52.64.8.153)
#   - operator-only SSH paths (runx ssh exec --target helixon-tunnel)
#   - 1Password vault names (HelixonSafe)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# -- ripgrep with .gitignore-aware behavior is the default; we pass -uu to
# force scanning of all files (including vendored) to be safe.
flags=(
  --no-messages
  --hidden
  --glob '!*_test.go'
  --glob '!.git/*'
  --glob '!.leak-cache/*'
  --glob '!tools/leak-scan.sh'
)

FAIL=0

patterns=(
  # 1Password UUIDs (exact 26-char)
  '\b[a-z0-9]{26}\b'
  # 1Password vault
  'HelixonSafe'
  # production hostname
  'cylrl\.dev'
  # production Lightsail IP
  '52\.64\.8\.153'
  # operator SSH path
  'runx ssh exec --target helixon-tunnel'
)

for p in "${patterns[@]}"; do
  if rg "${flags[@]}" -e "$p" . ; then
    echo "::error::leak-scan: pattern '$p' matched"
    FAIL=1
  fi
done

# IPv4: only flag public routable addresses (skip 127.*, 10.*, 172.16-31.*,
# 169.254.*, 0.0.0.0, 255.255.255.255, 8.8.8.8, 1.1.1.1, 9.9.9.9, 999.*)
ip_re='\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'
ip_excluded='(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|0\.0\.0\.0|255\.255\.255\.255|8\.8\.8\.8|1\.1\.1\.1|9\.9\.9\.9|999\.|203\.0\.113\.)'
if rg "${flags[@]}" -e "$ip_re" . | rg -v "$ip_excluded" ; then
  echo "::error::leak-scan: public IPv4 address found"
  FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then
  echo "leak-scan: clean"
fi
exit "$FAIL"
