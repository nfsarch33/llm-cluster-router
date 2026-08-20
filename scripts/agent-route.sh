#!/usr/bin/env bash
# agent-route.sh — one-boolean on/off switch per coding agent.
#
#   agent-route.sh                    show every agent flag
#   agent-route.sh codex on           enable an agent's route
#   agent-route.sh cursor off         disable an agent's route
#
# Edits the `agents:` map in the smartroute policy, validates the result,
# and reloads the router. The gate itself lives in internal/smartroute:
# an agent flagged false gets 403 at the router; anything else passes.
set -euo pipefail

POLICY="${SMARTROUTE_POLICY:-$HOME/.config/llm-router/smartroute.yml}"
AGENT="${1:-}"
STATE="${2:-}"

if [[ ! -f "$POLICY" ]]; then
  echo "policy not found: $POLICY (set SMARTROUTE_POLICY to override)" >&2
  exit 1
fi

show() {
  python3 - "$POLICY" <<'PY'
import sys, yaml
p = yaml.safe_load(open(sys.argv[1])) or {}
agents = p.get("agents") or {}
if not agents:
    print("no agents section — every agent is allowed")
for name, val in agents.items():
    print(f"  {name:14s} {'ON' if val else 'OFF'}")
PY
}

if [[ -z "$AGENT" ]]; then
  echo "agent routes in $POLICY:"
  show
  exit 0
fi

case "$STATE" in
  on)  VALUE=true ;;
  off) VALUE=false ;;
  *) echo "usage: agent-route.sh [<agent> on|off]   (agents: cursor claude-code kilo-code codex ...)" >&2; exit 2 ;;
esac

python3 - "$POLICY" "$AGENT" "$VALUE" <<'PY'
import sys, yaml
path, agent, value = sys.argv[1], sys.argv[2].lower(), sys.argv[3] == "true"
p = yaml.safe_load(open(path)) or {}
p.setdefault("agents", {})[agent] = value
# Round-trip through the schema check the router itself performs at load:
# classes must exist with models, default_class must resolve.
classes = {c.get("name") for c in p.get("classes") or []}
assert p.get("default_class") in classes, "policy invalid: default_class missing"
with open(path, "w") as f:
    yaml.safe_dump(p, f, sort_keys=False)
print(f"{agent} -> {'ON' if value else 'OFF'}")
PY

# Reload the router so the flag takes effect now, not at next boot.
if systemctl --user is-active llm-router.service >/dev/null 2>&1; then
  systemctl --user restart llm-router.service
  sleep 2
  if curl -sf http://127.0.0.1:8787/healthz >/dev/null 2>&1; then
    echo "router reloaded, healthy"
  else
    echo "WARNING: router restarted but health probe failed — check journalctl --user -u llm-router" >&2
    exit 1
  fi
else
  echo "note: llm-router.service not active here; flag saved, reload the router to apply"
fi

echo "current flags:"
show
