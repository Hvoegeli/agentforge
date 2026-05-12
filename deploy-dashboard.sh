#!/usr/bin/env bash
#
# deploy-dashboard.sh — regenerate the AgentForge observability dashboard from the
# findings DB (seeded known findings + a fresh C1 floor against the live deployed
# Co-Pilot) and copy the rendered HTML to the box that serves it.
#
# The dashboard itself is a single self-contained HTML file; the box just needs a
# static file server behind basic auth (see the README / Caddyfile below).
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
#   AF_DB / AF_REPORTS / AF_OUT — local scratch paths
#   AF_REMOTE_DIR          — dir on the box the static server roots at (default: /opt/agentforge-dashboard)
#
# One-time box setup (standalone Caddy + a second Cloudflare quick tunnel so the
# dashboard gets its own HTTPS URL, separate from the Co-Pilot's):
#
#   apt-get install -y caddy            # or grab the binary from caddyserver.com
#   mkdir -p /opt/agentforge-dashboard
#   caddy hash-password --plaintext 'PICK-A-PASSWORD'      # copy the $2a$... hash
#   cat > /etc/caddy/Caddyfile <<'EOF'
#   :8088 {
#       root * /opt/agentforge-dashboard
#       file_server
#       basic_auth { viewer PASTE_THE_BCRYPT_HASH_HERE }
#   }
#   EOF
#   systemctl restart caddy && systemctl enable caddy
#   # then expose :8088 over its own HTTPS quick tunnel (separate from the Co-Pilot's):
#   nohup cloudflared tunnel --url http://localhost:8088 > /var/log/cloudflared-dashboard.log 2>&1 &
#   grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' /var/log/cloudflared-dashboard.log   # <- the dashboard URL
#
set -euo pipefail
cd "$(dirname "$0")"

TARGET_URL="${1:-${COPILOT_BASE_URL:-}}"
SSH_HOST="${2:-${AF_SSH_HOST:-root@178.156.242.153}}"
TARGET_SHA="${AF_TARGET_SHA:-copilot@1055abd71}"
DB="${AF_DB:-/tmp/af-dashboard.sqlite}"
REPORTS="${AF_REPORTS:-/tmp/af-dashboard-reports}"
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

echo "==> rendering dashboard -> $OUT"
uv run agentforge dashboard --db "$DB" --out "$OUT"

echo "==> uploading to $SSH_HOST:$REMOTE_DIR/index.html"
ssh "$SSH_HOST" "mkdir -p '$REMOTE_DIR'"
scp "$OUT" "$SSH_HOST:$REMOTE_DIR/index.html"
echo "done. (refresh the page on the box's dashboard URL.)"
