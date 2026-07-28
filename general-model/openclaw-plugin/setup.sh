#!/usr/bin/env bash
# One-command setup for the AURA Monitor plugin.
# Starts the host-side scorer and installs the live risk gate into an OpenClaw container.
#
# PREREQS
#   * OpenClaw running in Docker (Docker Desktop, OrbStack, or plain Linux Docker)
#   * python3 on the host with: pip install scikit-learn joblib
#
# USAGE
#   ./setup.sh                        # run from anywhere; paths resolve from this file
#
# EVERY SETTING IS AN ENV VAR, so this works on any machine:
#   AURA_CONTAINER    container name                  (default: openclaw-gateway)
#   AURA_PORT         host port for the scorer        (default: 5005)
#   AURA_SCORER_URL   URL the CONTAINER uses to reach the scorer
#                     (default: http://host.docker.internal:<AURA_PORT>/score)
#                     On plain Linux Docker host.docker.internal often does not exist;
#                     use the bridge gateway, e.g. http://172.17.0.1:5005/score
#   AURA_COMPOSE_DIR  docker compose project dir      (optional; falls back to
#                     `docker restart`, which is enough for a linked plugin)
#   AURA_FAIL_MODE    open|closed                     (default: open)
#
# UNINSTALL
#   docker exec "$AURA_CONTAINER" openclaw plugins uninstall aura-monitor
#   pkill -f scorer.py
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

# SCIGATEWAY_OPENCLAW_CONTAINER / OPENCLAW_COMPOSE_DIR are the older names; still
# honoured so existing setups do not break, but the AURA_* names are the documented ones.
CONTAINER="${AURA_CONTAINER:-${SCIGATEWAY_OPENCLAW_CONTAINER:-openclaw-gateway}}"
PORT="${AURA_PORT:-5005}"
SCORER_URL="${AURA_SCORER_URL:-http://host.docker.internal:${PORT}/score}"
COMPOSE_DIR="${AURA_COMPOSE_DIR:-${OPENCLAW_COMPOSE_DIR:-}}"
FAIL_MODE="${AURA_FAIL_MODE:-open}"

say() { printf '[aura-setup] %s\n' "$*"; }
die() { printf '[aura-setup] ERROR: %s\n' "$*" >&2; exit 1; }

say "1/5 checking prereqs..."
python3 -c "import sklearn, joblib" 2>/dev/null \
  || die "missing deps. Run: pip install scikit-learn joblib"
command -v docker >/dev/null || die "docker not found on PATH"
docker ps --format '{{.Names}}' | grep -qx "$CONTAINER" \
  || die "container '$CONTAINER' is not running. Set AURA_CONTAINER to its name.
         Running: $(docker ps --format '{{.Names}}' | tr '\n' ' ')"
[ -f "$HERE/../models/aura_behavioral.joblib" ] \
  || say "  ! models/aura_behavioral.joblib not found; scorer falls back to aura_general"

say "2/5 starting scorer on :$PORT ..."
pkill -f "$HERE/scorer.py" 2>/dev/null || true
sleep 1
AURA_PORT="$PORT" nohup python3 "$HERE/scorer.py" > "$HERE/scorer.log" 2>&1 &
for _ in $(seq 1 15); do
  curl -sf "http://localhost:$PORT/" >/dev/null && break
  sleep 1
done
curl -sf "http://localhost:$PORT/" >/dev/null \
  || die "scorer did not come up. See $HERE/scorer.log"
say "  scorer up on :$PORT"

say "3/5 installing plugin into $CONTAINER ..."
docker cp "$HERE/aura-monitor" "$CONTAINER:/home/node/aura-monitor"
docker exec -u root "$CONTAINER" chown -R 1000:1000 /home/node/aura-monitor
docker exec "$CONTAINER" openclaw plugins install --link /home/node/aura-monitor >/dev/null

say "4/5 enabling conversation access for reply scoring ..."
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
docker exec "$CONTAINER" cat /home/node/.openclaw/openclaw.json > "$TMP/oc.json"
SCORER_URL="$SCORER_URL" FAIL_MODE="$FAIL_MODE" python3 - "$TMP/oc.json" <<'PY'
import json, os, sys
path = sys.argv[1]
with open(path) as fh:
    cfg = json.load(fh)
entry = cfg.setdefault("plugins", {}).setdefault("entries", {}).setdefault("aura-monitor", {})
entry.setdefault("hooks", {})["allowConversationAccess"] = True
# Env the plugin reads at runtime, written here so the container needs no manual edit.
entry.setdefault("env", {}).update({
    "AURA_SCORER_URL": os.environ["SCORER_URL"],
    "AURA_FAIL_MODE": os.environ["FAIL_MODE"],
})
with open(path, "w") as fh:
    json.dump(cfg, fh, indent=2)
PY
docker cp "$TMP/oc.json" "$CONTAINER:/home/node/.openclaw/openclaw.json"
docker exec -u root "$CONTAINER" chown 1000:1000 /home/node/.openclaw/openclaw.json

say "5/5 restarting gateway ..."
if [ -n "$COMPOSE_DIR" ] && [ -d "$COMPOSE_DIR" ]; then
  ( cd "$COMPOSE_DIR" && docker compose restart "$CONTAINER" >/dev/null )
else
  docker restart "$CONTAINER" >/dev/null
fi
for _ in $(seq 1 20); do
  docker exec "$CONTAINER" openclaw plugins list >/dev/null 2>&1 && break
  sleep 1
done

if docker exec "$CONTAINER" openclaw plugins list 2>/dev/null | grep -qi aura; then
  say "aura-monitor loaded. The gate is live."
  say "  dashboard : http://localhost:$PORT/dashboard"
  say "  history   : http://localhost:$PORT/history"
  say "  logs      : tail -f $HERE/scorer.log"
else
  die "plugin not listed after restart. Check: docker exec $CONTAINER openclaw plugins list"
fi
