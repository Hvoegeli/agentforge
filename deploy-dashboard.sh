#!/usr/bin/env bash
#
# deploy-dashboard.sh — regenerate the AgentForge observability dashboard (+ the
# RESILIENCE.md hand-off doc) from the findings DB (seeded known findings + a fresh
# C1 floor against the live deployed Co-Pilot) and copy them to the box that serves
# the dashboard at its own public URL — separate from the OpenEMR / Co-Pilot URLs.
#
# The dashboard is a single self-contained HTML file; the box serves /opt/agentforge-dashboard/
# over a plain static server fronted by a Cloudflare quick tunnel.
#
# Usage:
#   COPILOT_USERNAME=Smith COPILOT_PASSWORD='...' ./deploy-dashboard.sh
#   COPILOT_USERNAME=Smith COPILOT_PASSWORD='...' ./deploy-dashboard.sh <target-url> <ssh-host>
#
# Args / env (all optional):
#   $1 / COPILOT_BASE_URL  — the deployed Co-Pilot base URL.  Note: the Co-Pilot is
#                            exposed via a Cloudflare *quick* tunnel, whose
#                            *.trycloudflare.com subdomain ROTATES on every
#                            `cloudflared` restart — pass the current one.
#   $2 / AF_SSH_HOST       — ssh target for the box that serves the dashboard
#                            (default: root@178.156.242.153)
#   AF_TARGET_SHA          — recorded on the attempts (default: copilot@1055abd71)
#   AF_DB / AF_OUT         — local scratch paths (the SQLite DB / the HTML out file)
#   AF_REPORTS             — where the generated vuln reports go (default: ./reports —
#                            committed alongside dashboard.html / RESILIENCE.md so the
#                            "Full report" links in those docs resolve)
#   AF_REMOTE_DIR          — dir on the box the static server roots at (default: /opt/agentforge-dashboard)
#
# Box setup (already done on 178.156.242.153 — two systemd units; recreate with
# the snippet below if you ever rebuild the box):
#
#   mkdir -p /opt/agentforge-dashboard
#   cat > /etc/systemd/system/agentforge-dashboard-http.service <<'UNIT'
#   [Unit]
#   Description=AgentForge observability dashboard - static file server
#   After=network.target
#   [Service]
#   ExecStart=/usr/bin/python3 -m http.server 8090 --bind 127.0.0.1 --directory /opt/agentforge-dashboard
#   Restart=always
#   RestartSec=3
#   [Install]
#   WantedBy=multi-user.target
#   UNIT
#   cat > /etc/systemd/system/agentforge-dashboard-tunnel.service <<'UNIT'
#   [Unit]
#   Description=AgentForge observability dashboard - Cloudflare quick tunnel
#   After=network.target agentforge-dashboard-http.service
#   Requires=agentforge-dashboard-http.service
#   [Service]
#   ExecStart=/usr/local/bin/cloudflared tunnel --url http://localhost:8090 --no-autoupdate
#   Restart=always
#   RestartSec=5
#   [Install]
#   WantedBy=multi-user.target
#   UNIT
#   systemctl daemon-reload
#   systemctl enable --now agentforge-dashboard-http.service agentforge-dashboard-tunnel.service
#   # the public dashboard URL (rotates if the tunnel restarts — submit the current one):
#   journalctl -u agentforge-dashboard-tunnel -n 50 | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com'
#
set -euo pipefail
cd "$(dirname "$0")"

TARGET_URL="${1:-${COPILOT_BASE_URL:-}}"
SSH_HOST="${2:-${AF_SSH_HOST:-root@178.156.242.153}}"
TARGET_SHA="${AF_TARGET_SHA:-copilot@1055abd71}"
DB="${AF_DB:-/tmp/af-dashboard.sqlite}"
REPORTS="${AF_REPORTS:-reports}"
OUT="${AF_OUT:-dashboard.html}"
REMOTE_DIR="${AF_REMOTE_DIR:-/opt/agentforge-dashboard}"

if [[ -z "$TARGET_URL" ]]; then
  echo "deploy-dashboard.sh: need the deployed Co-Pilot URL — pass it as \$1 or set COPILOT_BASE_URL" >&2
  echo "  (it's a *.trycloudflare.com quick-tunnel URL and it rotates; grab the current one from the box)" >&2
  exit 2
fi

rm -f "$DB"; rm -rf "$REPORTS"
echo "==> seeding the known Co-Pilot findings"
uv run agentforge seed-findings --db "$DB" --reports-dir "$REPORTS"

echo "==> live C1 floor against the deployed target ($TARGET_URL)"
# `agentforge run` exits 0 even if the target is unhealthy (attempts get marked
# UNCERTAIN, not crashed), so this won't trip `set -e`.
uv run agentforge run --category C1 --target-url "$TARGET_URL" --target-sha "$TARGET_SHA" \
  --db "$DB" --reports-dir "$REPORTS"

echo "==> rendering dashboard -> $OUT (+ RESILIENCE.md)"
uv run agentforge dashboard --db "$DB" --out "$OUT" --resilience-md RESILIENCE.md

echo "==> uploading to $SSH_HOST:$REMOTE_DIR/index.html"
ssh "$SSH_HOST" "mkdir -p '$REMOTE_DIR'"
scp "$OUT" "$SSH_HOST:$REMOTE_DIR/index.html"
echo "done. (refresh the page on the box's dashboard URL; commit the regenerated dashboard.html + RESILIENCE.md + reports/.)"
