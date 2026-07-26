#!/usr/bin/env bash
# One-command setup for the AURA Monitor plugin.
# Starts the scorer service and installs the live risk gate into OpenClaw.
#
# Prereqs: OpenClaw running in Docker (container `openclaw-gateway`),
#          python3 with scikit-learn + joblib on the host.
# Usage:   ./setup.sh          (from openclaw-plugin/)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CONTAINER="${SCIGATEWAY_OPENCLAW_CONTAINER:-openclaw-gateway}"
COMPOSE_DIR="${OPENCLAW_COMPOSE_DIR:-$HOME/Documents/openclaw-docker}"

echo "[aura-setup] 1/5 checking prereqs..."
python3 -c "import sklearn, joblib" 2>/dev/null || { echo "  ! need: pip install scikit-learn joblib"; exit 1; }
docker ps --format '{{.Names}}' | grep -q "$CONTAINER" || { echo "  ! $CONTAINER not running"; exit 1; }

echo "[aura-setup] 2/5 starting scorer service on :5005..."
pkill -f "$HERE/scorer.py" 2>/dev/null || true; sleep 1
nohup python3 "$HERE/scorer.py" > "$HERE/scorer.log" 2>&1 &
sleep 3
curl -sf http://localhost:5005/ >/dev/null && echo "  scorer up" || { echo "  ! scorer failed — see $HERE/scorer.log"; exit 1; }

echo "[aura-setup] 3/5 installing plugin into $CONTAINER..."
docker cp "$HERE/aura-monitor" "$CONTAINER:/home/node/aura-monitor"
docker exec -u root "$CONTAINER" chown -R 1000:1000 /home/node/aura-monitor
docker exec "$CONTAINER" openclaw plugins install --link /home/node/aura-monitor >/dev/null

echo "[aura-setup] 4/5 enabling conversation access for reply scoring..."
docker exec "$CONTAINER" cat /home/node/.openclaw/openclaw.json > /tmp/aura_oc.json
python3 - <<PY
import json
d=json.load(open("/tmp/aura_oc.json"))
d.setdefault("plugins",{}).setdefault("entries",{}).setdefault("aura-monitor",{}).setdefault("hooks",{})["allowConversationAccess"]=True
json.dump(d,open("/tmp/aura_oc.json","w"),indent=2)
PY
docker cp /tmp/aura_oc.json "$CONTAINER:/home/node/.openclaw/openclaw.json"
docker exec -u root "$CONTAINER" chown 1000:1000 /home/node/.openclaw/openclaw.json

echo "[aura-setup] 5/5 restarting gateway..."
( cd "$COMPOSE_DIR" && docker compose restart "$CONTAINER" >/dev/null ); sleep 8
docker exec "$CONTAINER" openclaw plugins list 2>/dev/null | grep -qi aura && echo "  aura-monitor loaded" || echo "  ! plugin not listed"
echo "[aura-setup] done. The gate is live. Tail scorer: tail -f $HERE/scorer.log"
