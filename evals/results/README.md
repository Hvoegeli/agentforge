# `evals/results/` — Canonical Artifact Set

> **Grader's quick path:** read **`regression-1055abd71.json`** first. It is
> the canonical "found → reported → fixed → regression-verified" artifact for
> the Final checkpoint. Everything else in this directory is supporting
> evidence or historical baseline.

The two **`*1055abd71*`** artifacts in this directory are the
**committed, reproducible proofs** that AgentForge ran against the deployed
Co-Pilot at a pinned target SHA. They each carry `target_base_url` and
`target_sha` — at the top level in `regression-1055abd71.json`, and inside
each `runs[]` element in `c4-c6-live-1055abd71.json`. The third file
(`seeded-baseline.json`) is a pre-live-target snapshot and **doesn't** carry
those fields; treat it as historical baseline, not as cross-process proof.

| File | Date | Purpose | Status |
|---|---|---|---|
| **`regression-1055abd71.json`** | 2026-05-14 | **CANONICAL** — full regression suite: **6 seeded findings × 10 replays each = 60 attempts**, all against `copilot@1055abd71` on the deployed Hetzner instance. Top-level fields: `target_base_url`, `target_sha`, `n_replays_per_case = 10`, `summary.n_holding = 5`, `summary.n_failing = 1`, `summary.status_updates_written = true`. **5 of 6 cases hold cleanly (10/10 clear)** and flip to `resolved`; **1 case (B1.zero-citation) shows judge/transport noise at N=10** (6/10 clear, 4 uncertain, 2 of those with errors) — no invariant violation, but the suite couldn't confirm a clean clear, so the finding stays `open`. This is the suite working as designed: a smaller N=3 sample previously masked this noise, and the larger sample surfaced it. See `MVP_EVIDENCE.md` §1c for the full discussion. | **read this first** |
| `c4-c6-live-1055abd71.json` | 2026-05-12 | Two focused live campaign records (C4 + C6, RunRecord shape) — **per-run fields are nested** under `runs[]`: `runs[].target_base_url`, `runs[].target_sha`, `runs[].started_at` / `runs[].finished_at`, `runs[].n_attacks`, `runs[].halted_reason`. Demonstrates a single live campaign's data shape; pair with `regression-1055abd71.json` for the full picture. | supporting |
| `seeded-baseline.json` | 2026-05-12 | Day-one snapshot from `agentforge seed-findings` (the 6 known weaknesses re-replayed through the deterministic invariant checkers, no live target involved). Carries no `target_base_url` / `target_sha` (it's a pre-live-target snapshot). Historical baseline; **NOT** evidence of live-target attack — the live-target proofs are the two `*1055abd71*` files above. | historical baseline |

## How to regenerate

Every file in this directory is produced by a documented CLI:

```bash
# regenerate regression-<sha>.json (the canonical Final artifact)
uv run agentforge regression-suite \
  --db /tmp/grader.sqlite \
  --target-url https://hansen-rat-ages-rim.trycloudflare.com \
  --target-sha copilot@1055abd71 \
  --n 10 --update-status \
  --out evals/results/regression-1055abd71.json

# regenerate c4-c6-live-<sha>.json — two live campaign records (C4 + C6)
# Note: `agentforge run` writes to the SQLite DB; the JSON in evals/results/
# is exported from the DB. See the file's own `_reproduce` top-level field
# for the exact two commands and the DB → JSON export step that produced it.
uv run agentforge run --category C4 \
  --target-url https://hansen-rat-ages-rim.trycloudflare.com \
  --target-sha copilot@1055abd71 \
  --db /tmp/grader.sqlite
uv run agentforge run --category C6 \
  --target-url https://hansen-rat-ages-rim.trycloudflare.com \
  --target-sha copilot@1055abd71 \
  --db /tmp/grader.sqlite

# regenerate seeded-baseline.json — the deterministic baseline (no live target)
uv run agentforge seed-findings --db /tmp/seed.sqlite --reports-dir /tmp/reports
```

The full sweep is wrapped in [`../../deploy-dashboard.sh`](../../deploy-dashboard.sh)
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
