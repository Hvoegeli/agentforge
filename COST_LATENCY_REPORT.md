# AgentForge — Cost & Latency Report

> **Scope.** This report projects AgentForge's **agent-side LLM cost** — the spend
> the platform's budget controls — at **100 / 1 000 / 10 000 / 100 000 runs**, and
> the per-run latency profile. It does *not* count the target Clinical Co-Pilot's
> own inference cost (that is the Co-Pilot's budget; AgentForge records it
> separately as `target_llm_cost_usd` for visibility but never pays it).
>
> **Status:** the projection table is built from the **cost model** below; the
> measured-from-a-100-run column is filled in after the first 100-run sample
> (`agentforge run …` ×100, then read `RunRecord.total_cost_usd` and the
> `agentforge.llm` running total). Until then, treat the numbers as the *upper
> bound the model predicts*, not measured fact. Week-3 budget envelope: **$10–50**.

## The cost model — where money is (and isn't) spent

AgentForge has a **free deterministic floor** and a **paid mutation/judgement layer**:

| Layer | What it does | LLM calls? | Cost |
|---|---|---|---|
| Deterministic seed corpus (`attacks/seeds.py`) | curated AttackCases per category | none | **$0** |
| Deterministic mutators (`attacks/red_team.py`) | 6 transforms on a near-miss turn | none | **$0** |
| Deterministic invariant checkers (`invariants/`) | the Judge's primary path (C1 canary/sentinel, C2 ID-set, C4 trace, C5 meters, C6 disclaimer, B3 LCS) | none | **$0** |
| Target Adapter (`target/adapter.py`) | executes the attack against the Co-Pilot | none (the *target* runs LLMs, not us) | **$0 to us** |
| LLM mutation (`Role.MUTATION`) | extra adversarial variants of a near-miss, when `--mutate` + `mutate_with_llm` | yes — Qwen3-32B | per near-miss |
| LLM-Judge (`Role.JUDGE`) | semantic verdicts on the `UNCERTAIN` cases (C1 guardrail-bypass, C6 persona, C3 provenance, B1 clinical-claim detection) | yes — Mistral-Large-2411 | per uncertain semantic case |
| LLM report narrative (`Role.DOCUMENTATION`) | Summary/Impact prose for a confirmed finding (facts come from the records; LLM only writes two paragraphs) | yes — Llama-3.1-8B | per confirmed finding |

So per-run agent cost ≈

```
cost_run ≈  n_llm_mutations(run)        × c_mutation
          + n_semantic_uncertain(run)   × c_judge
          + n_confirmed_findings(run)   × c_doc
```

A **pure-deterministic campaign costs $0** — that is the reproducible, auditable
floor the platform always runs (and what CI runs). LLM spend is *opt-in* per
campaign (`--mutate`, an LLM-Judge-enabled Judge, an LLM-narrative Documentation
agent) and scales with *signal*, not with attack count: more near-misses and
more confirmed findings ⇒ more LLM calls; a clean target is cheap.

### Per-call cost inputs (placeholders — verify at openrouter.ai/models)

From `agentforge/llm.py::_PRICE_TABLE` (USD per million tokens, input/output):

| Role → model | in $/Mtok | out $/Mtok | typical call (in/out tok) | ≈ $/call |
|---|---|---|---|---|
| MUTATION → `qwen/qwen3-32b` | 0.10 | 0.30 | 1 200 / 800 | ~$0.00036 |
| JUDGE → `mistralai/mistral-large-2411` | 2.00 | 6.00 | 1 500 / 400 | ~$0.0054 |
| DOCUMENTATION → `meta-llama/llama-3.1-8b-instruct` | 0.06 | 0.06 | 1 100 / 500 | ~$0.00010 |

(RED_TEAM attack-generation — WhiteRabbitNeo-70B at ~$0.90/Mtok — is used only when
the LLM Red Team is enabled; the MVP runs the deterministic seed floor, so it does
not contribute to the figures below.)

## Projection

Assumptions for the projection (to be replaced by the 100-run measurement):
a "run" = one Orchestrator campaign over a category's deterministic floor (~6–9
attacks); near-miss rate ~15% with `--mutate` on (so ~1 LLM-mutation pass/run if
`mutate_with_llm`); ~10% of attacks land on a semantic-uncertain invariant needing
the LLM-Judge (~1 judge call/run); ~1 confirmed finding per ~3 runs (~0.33 doc
calls/run). Conservative: assume the **judge call dominates**.

| Runs | Deterministic-only (CI default) | With LLM-Judge only | With LLM-Judge + LLM-mutation + LLM-narrative | Notes |
|---|---|---|---|---|
| 100 | **$0.00** | ~$0.54 | ~$0.60 | the 100-run sample we measure |
| 1 000 | **$0.00** | ~$5.40 | ~$6.00 | within the week budget on its own |
| 10 000 | **$0.00** | ~$54 | ~$60 | rate cap (20 attacks/min) makes this ~6–8 h of wall time, not a cost spike |
| 100 000 | **$0.00** | ~$540 | ~$600 | linear in *signal*; if the target is clean, far less — most cost is judge calls on real ambiguity |

**What is NOT linear:** (1) the deterministic floor is flat $0 regardless of run
count; (2) near-miss mutation amplifies only when attacks come *close* — a hardened
target produces fewer near-misses, so cost *falls* as the target improves; (3) the
20-attacks/min rate cap bounds throughput, so at 10k+ runs wall-clock time, not
dollars, is the binding constraint; (4) the LLM-Judge is only invoked on the
residual `UNCERTAIN` semantic cases — every case a deterministic checker can
adjudicate is free.

## Latency profile (per attack)

| Stage | Deterministic path | LLM path |
|---|---|---|
| Target Adapter `attack()` | the Co-Pilot's turn latency (dominant) — p50 ~1–4 s single-turn, more for multi-turn / document expansion; per-call timeout 60 s, per-turn run timeout 120 s (300 s multi-turn) | same |
| Judge | ~0 ms (regex / set-membership / DP-LCS) | +1–3 s (one Mistral-Large call, temperature 0) |
| Documentation (only on FAIL) | ~0 ms (template) | +1–2 s (one Llama-8B call) |
| Rate limiter | enforces ≤ 20 attacks/min (≥ 3 s min interval) | same |

Throughput is therefore **rate-limited at ~20 attacks/min** regardless of the LLM
path; the LLM calls add seconds to an individual attack but do not change the
campaign-level throughput, which the rate cap pins. A full deterministic C1
campaign (~9 attacks) completes in well under a minute of compute (rate-cap
notwithstanding) at $0.

## How to refresh this report

```bash
# 1. run a representative 100-run sample (mix of categories), recording the DB
for i in $(seq 1 100); do
  agentforge run --category C1 --db data/cost_sample.sqlite --reports-dir /tmp/cost_reports
  # ... vary --category / --mutate across the 100 ...
done
# 2. read the agent-side cost out of the runs table + the llm running total
sqlite3 data/cost_sample.sqlite "SELECT SUM(total_cost_usd), COUNT(*) FROM runs;"
# 3. divide → cost_per_run; multiply → the table above; commit the measured column
```
