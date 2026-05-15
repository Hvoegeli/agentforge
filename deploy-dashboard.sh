#!/usr/bin/env bash
#
# deploy-dashboard.sh — regenerate the AgentForge observability dashboard (+ the
# RESILIENCE.md hand-off doc) from the findings DB (seeded known findings + a fresh
# floor across ALL NINE attack categories against the live deployed Co-Pilot) and
# copy them to the box that serves the dashboard at its own public URL — separate
# from the OpenEMR / Co-Pilot URLs.
#
# Each run is tagged on the dashboard with the environment it executed against
# ("deployed instance" here; "local stack" for runs you do against a local dev
# Co-Pilot). By default this script starts from a fresh DB (so `seed-findings`
# stays idempotent); set AF_KEEP_DB=1 (and point AF_DB at the DB that holds your
# local exploratory runs) to keep prior runs and have them appear, tagged
# "local stack", alongside this deployed-instance sweep.
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
#   AF_CATEGORIES          — space-separated category list to sweep
#                            (default: "C1 C2 C3 C4 C5 C6 B1 B2 B3" — all nine)
#   AF_KEEP_DB             — set to 1 to NOT wipe AF_DB first (keeps prior runs, e.g.
#                            local exploratory runs, so they appear on the dashboard
#                            tagged "local stack"); default wipes for a fresh snapshot
#   AF_SKIP_REGRESSION     — set to 1 to skip the post-sweep regression-suite step
#   AF_REGRESSION_N        — replays per in-suite case (default: 10 — N=10 is the
#                            canonical setting; we previously ran N=3 but the smaller
#                            sample masked judge/transport flakiness on the B1
#                            zero-citation invariant, which N=10 surfaces)
#   AF_REGRESSION_OUT      — regression artifact path (default: evals/results/regression-<sha>.json)
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

# Categories to sweep, in the dashboard's C1..C6/B1..B3 order. Override with
# AF_CATEGORIES="C1 C5 ..." to run a subset.
CATEGORIES="${AF_CATEGORIES:-C1 C2 C3 C4 C5 C6 B1 B2 B3}"

if [[ -z "${AF_KEEP_DB:-}" ]]; then
  rm -f "$DB"
fi
rm -rf "$REPORTS"
echo "==> seeding the known Co-Pilot findings"
uv run agentforge seed-findings --db "$DB" --reports-dir "$REPORTS"

# `agentforge run` exits 0 even if the target is unhealthy (the campaign records
# a run with 0 attacks / halted_reason=target_unavailable, it doesn't crash), so
# the loop below won't trip `set -e`.
for cat in $CATEGORIES; do
  echo "==> live $cat floor against the deployed target ($TARGET_URL)"
  uv run agentforge run --category "$cat" --target-url "$TARGET_URL" --target-sha "$TARGET_SHA" \
    --db "$DB" --reports-dir "$REPORTS"
done

# Re-verify the seeded known findings against the deployed target: replay each
# in-suite case N times; a case that holds → its finding flips to `resolved`
# (the "found → reported → fixed → regression-verified" arc). `regression-suite`
# exits non-zero if any case doesn't hold (it's also a CI gate) — `|| true` so a
# still-open finding doesn't abort the deploy. Set AF_SKIP_REGRESSION=1 to skip.
REGRESSION_OUT="${AF_REGRESSION_OUT:-evals/results/regression-${TARGET_SHA##*@}.json}"
if [[ -z "${AF_SKIP_REGRESSION:-}" ]]; then
  echo "==> regression suite vs $TARGET_URL (update-status) -> $REGRESSION_OUT"
  uv run agentforge regression-suite --db "$DB" --target-sha "$TARGET_SHA" \
    --n "${AF_REGRESSION_N:-10}" --update-status --out "$REGRESSION_OUT" || true
fi

echo "==> rendering dashboard -> $OUT (+ RESILIENCE.md)"
uv run agentforge dashboard --db "$DB" --out "$OUT" --resilience-md RESILIENCE.md

echo "==> uploading to $SSH_HOST:$REMOTE_DIR/index.html"
ssh "$SSH_HOST" "mkdir -p '$REMOTE_DIR'"
scp "$OUT" "$SSH_HOST:$REMOTE_DIR/index.html"
echo "done. (refresh the page on the box's dashboard URL; commit the regenerated dashboard.html + RESILIENCE.md + reports/.)"
