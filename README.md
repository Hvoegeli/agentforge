# AgentForge

> An autonomous multi-agent adversarial-evaluation platform that continuously red-teams an LLM-assisted clinical chatbot.

## AgentForge is a standalone repository. Read this first.

**This repo ([`Hvoegeli/agentforge`](https://github.com/Hvoegeli/agentforge)) is the platform.** It is **not** part of OpenEMR and **not** part of the Clinical Co-Pilot it attacks. The Co-Pilot is a different repo entirely: [`Hvoegeli/openemr`](https://github.com/Hvoegeli/openemr). They have never shared a tree, a process, a database, or a CI pipeline.

```
┌────────────────────────────────┐                  ┌──────────────────────────────────────────┐
│ AgentForge — the platform      │                  │ Clinical Co-Pilot — the TARGET           │
│ github.com/Hvoegeli/agentforge │ ── HTTPS ──▶     │ github.com/Hvoegeli/openemr              │
│ this repo                      │   only           │ a different repo                         │
│                                │                  │                                          │
│ Deployed dashboard URL ↓       │                  │ Deployed target URL ↓                    │
│ asin-vessels-differ-drunk.     │                  │ hansen-rat-ages-rim.                     │
│   trycloudflare.com            │                  │   trycloudflare.com                      │
│ (systemd: agentforge-dashboard-*) │               │ (systemd: clinical-copilot-*, port 7300) │
└────────────────────────────────┘                  └──────────────────────────────────────────┘
```

**Different repos, different deployments, different Cloudflare tunnels, different `systemd` services on the box.** AgentForge reaches the Co-Pilot **only** through the Target Adapter ([`src/agentforge/target/adapter.py`](src/agentforge/target/adapter.py)) — an `httpx.Client` against an allowlisted external URL, rate-capped at 20/min, with transcripts PHI-redacted before storage. Every `AttackAttempt` in the SQLite store records `target_base_url` and `target_sha` so the cross-process round-trip is provable from the data.

> **For a runnable proof in three minutes — including `curl` to the target's `/healthz`, a live `agentforge run` showing outbound HTTPS, and a regression-suite invocation at the pinned target SHA — see [`MVP_EVIDENCE.md`](MVP_EVIDENCE.md).** That is the single grader-facing verification pack.

---

**Status:** MVP (2026-05-12) — platform built, 206 tests green, 6 seeded findings, all 9 attack categories exercised live against the deployed target (9/9 on the dashboard). Final: 2026-05-15.

- **Deployed target (Co-Pilot — the system being attacked):** `https://hansen-rat-ages-rim.trycloudflare.com/` — Cloudflare quick tunnel; the subdomain rotates on `cloudflared` restart, so the current URL is submitted with each checkpoint. Pinned baseline SHA for the regression suite: `74aa5be4` (openemr `master`); the live deployment currently runs `1055abd71` (the pen-test fixes — see [`THREAT_MODEL.md`](THREAT_MODEL.md) § *Fix status*).
- **Deployed AgentForge dashboard (this platform's own URL, *separate* from the Co-Pilot's):** `https://asin-vessels-differ-drunk.trycloudflare.com/` — the rendered observability dashboard, served from the Hetzner box behind its **own** Cloudflare quick tunnel (`systemd`: `agentforge-dashboard-http.service` serves `/opt/agentforge-dashboard/` on `:8090`, `agentforge-dashboard-tunnel.service` runs `cloudflared`). `RESILIENCE.md` is served at `/RESILIENCE.md`. Quick-tunnel subdomain rotates if `cloudflared` restarts — the current URL is submitted with each checkpoint; run `journalctl -u agentforge-dashboard-tunnel -n 50 | grep trycloudflare` on the box for the live one. Committed snapshot: [`dashboard.html`](dashboard.html). Companion hand-off doc [`RESILIENCE.md`](RESILIENCE.md) — per-category pass/fail + every open finding as a reproducible work list to give the Co-Pilot's maintainer; regenerate with `agentforge resilience-report`.
- **Companion docs:** [`MVP_EVIDENCE.md`](MVP_EVIDENCE.md) (the 3-minute verification pack), [`THREAT_MODEL.md`](THREAT_MODEL.md) (attack surface), [`ARCHITECTURE.md`](ARCHITECTURE.md) (multi-agent design + diagram), [`USERS.md`](USERS.md) (who uses it / why automation), [`evals/success_criteria.md`](evals/success_criteria.md) (the invariants), [`COST_LATENCY_REPORT.md`](COST_LATENCY_REPORT.md) (cost model + 100/1K/10K/100K projection), [`presearch.md`](presearch.md) (constraints + decisions).

## What it does

Four agents coordinate to continuously identify, evaluate, and document vulnerabilities in the target Clinical Co-Pilot, then convert each confirmed exploit into a permanent regression test:

- **Red Team agent** — generates and mutates adversarial inputs (single-turn and multi-turn); a deterministic floor (PyRIT / promptfoo / garak corpora + public datasets, plus a curated seed corpus) runs every cycle, with an open-weight security-specialty LLM invoked *only to mutate near-misses*.
- **Judge agent** — independent of the attack engine; renders pass/fail/partial/uncertain verdicts on **machine-checkable invariants** (a deterministic assertion per threat category, defined in [`evals/success_criteria.md`](evals/success_criteria.md)). For the residual cases that need semantic judgment, an LLM-judge runs against a labeled ground-truth corpus ([`evals/judge_corpus/`](evals/judge_corpus/)) with a measured agreement / FP / FN rate — and until that rate is established, its verdicts surface as *leads*, never auto-filed findings.
- **Orchestrator agent** — reads the observability state (coverage gaps, open high-severity findings, recent regressions, cost burn) and decides what to attack next. Owns the rate cap, the cost-without-signal kill switch, and the regression-replay trigger. LangGraph `StateGraph` ties the loop together.
- **Documentation agent** — converts a confirmed `Finding` + its Judge verdict into a structured, reproducible vulnerability report (OWASP / MITRE ATLAS / NIST refs, clinical impact, minimal repro, observed-vs-expected, remediation, fix-validation status); auto-files HIGH-and-below, holds CRITICAL as a draft for human approval.

Plus a **regression harness** (SQLite findings DB; every confirmed exploit becomes a deterministic replay that asserts the *invariant*, not the output string) and an **observability layer** (JSONL trace log + the static HTML dashboard).

## Why open-weight / no main LLMs

Frontier proprietary models tend to refuse, soften, or hallucinate when asked to generate adversarial inputs even under explicit authorized-pentest framing — which makes coverage numbers fiction. The deterministic floor (PyRIT + promptfoo + garak corpora + public datasets like HarmBench / JailbreakBench / AdvBench + a curated technique corpus) runs on every cycle and is reproducible, auditable, and cheap; the LLM is invoked only to mutate near-misses, via [OpenRouter](https://openrouter.ai/) (open-weight security-specialty models for the Red Team; a *different model family* for the Judge, so the judge is independent by design) — with Ollama for free local dev iteration.

| Role | Model | Why |
|---|---|---|
| Red Team — attack generation | **WhiteRabbitNeo-2-70B** | Llama-3 fine-tune purpose-built for authorized security testing |
| Red Team — mutation / planning | **Qwen3-32B** / DeepSeek-V3 | Strong agentic reasoning; structural, not refusal-prone |
| Judge — semantic-judgment cases | **Mistral-Large-2** / Foundation-Sec-8B | *Different family* from the Red Team → independent judge by design |
| Documentation | **Llama-3.1-8B-Instruct** | Templated markdown fill-in; cheap |

## Standards we map to

We operationalize known taxonomies; we don't invent new ones.

- [**OWASP Top 10 for LLM Applications 2025**](https://genai.owasp.org/llm-top-10/) — the threat-model spine
- [**MITRE ATLAS**](https://atlas.mitre.org/) — TTP IDs for vulnerability reports
- [**NIST AI 600-1** (Generative AI Profile)](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) — governance vocabulary
- [**OWASP Agentic-AI / Multi-Agentic System Threat Modeling Guide**](https://genai.owasp.org/resource/multi-agentic-system-threat-modeling-guide-v1-0/) — multi-agent-specific threats

## Project layout

```
agentforge/
├── README.md                 (this file)
├── ARCHITECTURE.md           (multi-agent design + agent-interaction diagram)
├── THREAT_MODEL.md           (full attack-surface map + Framework Mapping Chart + Fix status)
├── USERS.md                  (who uses AgentForge, workflows, why automation)
├── COST_LATENCY_REPORT.md    (agent-side cost model + 100/1K/10K/100K projection)
├── presearch.md              (planning doc — constraints, decisions, open questions)
├── dashboard.html            (rendered observability dashboard — static, self-contained)
├── RESILIENCE.md             (generated: per-category pass/fail + open-findings work list for the target's maintainer)
├── deploy-dashboard.sh       (regenerate the dashboard + RESILIENCE.md from a live run + scp the dashboard to the box)
├── reports/                  (the 6 generated vulnerability reports — all filed; the 2 CRITICALs were reviewed & signed off, so reports/drafts/ is empty. A Red-Team-discovered CRITICAL would land in reports/drafts/ until approved.)
├── evals/
│   ├── success_criteria.md   (the invariant table — the Judge's spec)
│   ├── judge_corpus/         (labeled ground-truth transcripts — the Judge validation set)
│   ├── thresholds.yaml       (token / cost / wall-time / hop / amplification thresholds for the DoS invariants)
│   └── results/              (committed run artifacts)
├── src/agentforge/           (Python package — uv project)
│   ├── models.py             (the Pydantic contracts between agents)
│   ├── cli.py                (entrypoint: run / status / replay / validate-judge / dashboard / resilience-report / seed-findings / regression-suite)
│   ├── config.py             (settings + the target-host allowlist)
│   ├── llm.py                (OpenRouter / Ollama model router)
│   ├── known_findings.py     (the 6 seeded Co-Pilot findings — 4 day-one + 2 from the 2026-05-12 pen-test)
│   ├── target/               (Target Adapter — HTTP client, host allowlist, rate cap, redaction)
│   ├── attacks/              (deterministic floor — PyRIT/promptfoo/garak wrappers + curated corpus + the Red Team agent + LLM mutation + poisoned-doc rendering)
│   ├── invariants/           (the deterministic checkers, one per success_criteria invariant + thresholds loader)
│   ├── judge/                (the Judge agent + LLM-Judge + the corpus-validation harness)
│   ├── documentation/        (the Documentation agent + report templates)
│   ├── orchestrator/         (the Orchestrator agent + LangGraph StateGraph + the priority heuristic)
│   ├── regression/           (the Regression Curator + Suite — replay_case / replay_finding)
│   ├── storage/              (SQLite findings DB + JSONL trace writer)
│   ├── observability/        (metrics computation for the dashboard)
│   └── dashboard/            (Jinja2 render → static HTML)
├── tests/                    (pytest — 201 tests)
├── .github/workflows/        (ci.yml)
├── LICENSE                   (MIT)
└── pyproject.toml / uv.lock / .env.example / .python-version
```

## Run instructions

Requires [`uv`](https://docs.astral.sh/uv/). From the repo root:

```bash
uv sync                                 # install deps
uv run pytest -q                        # run the test suite
uv run ruff check src/ tests/           # lint

# seed the 6 known Co-Pilot findings (case + attempt + real deterministic verdict + vuln report) into a findings DB
uv run agentforge seed-findings --db findings.sqlite --reports-dir reports/

# run a campaign live against the deployed target (the Orchestrator picks the next category if you omit --category)
COPILOT_USERNAME=<test-account> COPILOT_PASSWORD=<password> \
  uv run agentforge run --category C1 \
    --target-url https://<current-trycloudflare-url> --target-sha copilot@1055abd71 \
    --db findings.sqlite --reports-dir reports/

uv run agentforge status --db findings.sqlite          # coverage / verdict rates / open findings / recent runs
uv run agentforge validate-judge                        # corpus-validate the Judge (agreement / FP / FN)
uv run agentforge replay --finding <id> --n 10 --target-url <url>   # regression-replay one finding's case
# replay the whole regression suite at the post-fix SHA — the "found → reported → fixed → regression-verified" artifact:
uv run agentforge regression-suite --db findings.sqlite --target-url <deployed-url> --target-sha copilot@1055abd71 \
  --out evals/results/regression-1055abd71.json --update-status   # resolves the cases that now hold; flags any regression; exits non-zero if any case fails
uv run agentforge dashboard --db findings.sqlite --out dashboard.html --resilience-md RESILIENCE.md   # render the observability dashboard (+ the RESILIENCE.md work list)
uv run agentforge resilience-report --db findings.sqlite --out RESILIENCE.md   # just the hand-off doc

# one command: re-seed findings + fresh C1 floor against the live target + render + scp the dashboard to the box
COPILOT_USERNAME=<test-account> COPILOT_PASSWORD=<password> ./deploy-dashboard.sh <current-trycloudflare-url>
```

The Target Adapter only constructs against an allowlisted host (`localhost` / the box IP / `*.trycloudflare.com`) — AgentForge attacks the one authorized Co-Pilot target, never anything else. Synthetic patient data only; rate-capped (≤ 20 attacks/min); transcripts redacted before storage; CRITICAL findings held as drafts pending human approval.

See [`evals/success_criteria.md`](evals/success_criteria.md) for exactly what each invariant checks, [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full attack-surface map, and [`ARCHITECTURE.md`](ARCHITECTURE.md) for the multi-agent design.

## Roadmap (post-Friday)

1. Production-grade Judge corpus (200+ hand-adjudicated cases from real redacted transcripts).
2. Live re-execution for the HTTP-setup findings (`raw_http_get` / `session_adoption`) + an admin observability account so C4/C5 trace enrichment works against the patched target.
3. Langfuse trace integration for agent-level debugging.
4. Deeper PyRIT / garak / promptfoo coverage.
5. Plug-in for the openemr fork's CI to gate on AgentForge's regression suite.

## License

[MIT](LICENSE)
