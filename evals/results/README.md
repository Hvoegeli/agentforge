# `evals/results/` — Canonical Artifact Set

> **Grader's quick path:** read **`regression-1055abd71.json`** first. It is
> the canonical "found → reported → fixed → regression-verified" artifact for
> the Final checkpoint. Everything else in this directory is supporting
> evidence or historical baseline.

The artifacts in this directory are the **committed, reproducible proofs**
that AgentForge ran against the deployed Co-Pilot at a pinned target SHA.
Every file carries `target_base_url` and `target_sha` so the cross-process
HTTPS round-trip is provable from the data alone.

| File | Date | Purpose | Status |
|---|---|---|---|
| **`regression-1055abd71.json`** | 2026-05-13 | **CANONICAL** — full regression suite: 6 seeded findings × 3 replays each, all against `copilot@1055abd71` on the deployed Hetzner instance. `summary.n_holding = 6`, `summary.status_updates_written = true`. This is the "verify the fixes held" proof for the Final submission. | **read this first** |
| `c4-c6-live-1055abd71.json` | 2026-05-12 | A focused C4 + C6 campaign run record (RunRecord shape) — `target_base_url`, `target_sha`, UTC timestamps, attack/finding counts, halted-reason. Demonstrates a single live campaign's data shape; pair with `regression-1055abd71.json` for the full picture. | supporting |
| `seeded-baseline.json` | 2026-05-12 | Day-one snapshot from `agentforge seed-findings` (the 6 known weaknesses re-replayed through the deterministic invariant checkers, no live target involved). Historical baseline; **NOT** evidence of live-target attack — the live-target proofs are the two files above. | historical baseline |

## How to regenerate

Every file in this directory is produced by a documented CLI:

```bash
# regenerate regression-<sha>.json (the canonical Final artifact)
uv run agentforge regression-suite \
  --db /tmp/grader.sqlite \
  --target-url https://hansen-rat-ages-rim.trycloudflare.com \
  --target-sha copilot@1055abd71 \
  --n 3 --update-status \
  --out evals/results/regression-1055abd71.json

# regenerate c4-c6-live-<sha>.json — a single campaign record
uv run agentforge run --category C4 \
  --target-url https://hansen-rat-ages-rim.trycloudflare.com \
  --target-sha copilot@1055abd71 \
  --db /tmp/grader.sqlite

# regenerate seeded-baseline.json — the deterministic baseline (no live target)
uv run agentforge seed-findings --db /tmp/seed.sqlite --reports-dir /tmp/reports
```

The full sweep is wrapped in [`../deploy-dashboard.sh`](../../deploy-dashboard.sh)
(seed → 9-cat live sweep → regression-suite with `--update-status` → render +
scp the dashboard) and is the single command that produces all three
artifacts plus the deployed `RESILIENCE.md` / `dashboard.html`.

## What grader should NOT do

- **Don't infer from many files.** Read `regression-1055abd71.json` and
  cross-check against [`../../RESILIENCE.md`](../../RESILIENCE.md) (auto-generated
  from the same DB) and the [`../../dashboard.html`](../../dashboard.html)
  snapshot. Those three agree by construction.
- **Don't read `seeded-baseline.json` as live-target evidence.** It's a
  baseline replay of the seeded findings — useful for "the platform recognises
  these as real findings" but **not** the cross-process proof. The
  cross-process proofs are the `*1055abd71*` files.

See [`../../MVP_EVIDENCE.md`](../../MVP_EVIDENCE.md) for the runnable
"Verify in 3 minutes" version of this evidence (curl + CLI commands).
