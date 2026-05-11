# AgentForge

> An autonomous multi-agent adversarial-evaluation platform that continuously red-teams an LLM-assisted clinical chatbot.

**Status:** Pre-MVP scaffold · Architecture-defense checkpoint 2026-05-11 · MVP 2026-05-12 · Final 2026-05-15

**Target system (the "victim"):** the [OpenEMR Clinical Co-Pilot](https://github.com/Hvoegeli/openemr) (Weeks 1–2 build), deployed on Hetzner. AgentForge reaches the target over HTTP — exactly like an external attacker would — and never shares a process, a database, or a CI pipeline with it.

## What it does

Four agents coordinate to continuously identify, evaluate, and document vulnerabilities in the target Clinical Co-Pilot, then convert each confirmed exploit into a permanent regression test:

- **Red Team agent** — generates and mutates adversarial inputs (single-turn and multi-turn); wraps PyRIT (Microsoft) and promptfoo (OWASP-LLM-Top-10 plugins) as the deterministic attack engine, with an open-weight security-specialty LLM (WhiteRabbitNeo) for creative variant generation only on near-misses.
- **Judge agent** — independent of the attack engine; renders pass/fail/partial verdicts on **machine-checkable invariants** (a deterministic assertion per threat category, defined in [`evals/success_criteria.md`](evals/success_criteria.md)). For the residual cases that need semantic judgment, an LLM-judge runs against a labeled ground-truth corpus with a measured agreement / FP / FN rate.
- **Orchestrator agent** — reads the observability state (coverage gaps, open high-severity findings, recent regressions, cost burn) and decides what to attack next. Owns the rate cap, the cost-without-signal kill switch, and the regression-replay trigger.
- **Documentation agent** — converts a confirmed exploit + its Judge verdict into a structured, reproducible vulnerability report.

Plus a **regression harness** (SQLite findings DB; every confirmed exploit becomes a deterministic replay at a pinned target SHA) and an **observability layer** (JSONL trace log + a static HTML dashboard, deployed read-mostly under basic auth).

## Why open-weight / no main LLMs

Frontier proprietary models (Claude / GPT / Gemini direct) tend to refuse, soften, or hallucinate when asked to generate adversarial inputs even under explicit authorized-pentest framing — which makes coverage numbers fiction. AgentForge uses open-weight models via [OpenRouter](https://openrouter.ai/):

| Role | Model | Why |
|---|---|---|
| Red Team — attack generation | **WhiteRabbitNeo-2-70B** | Llama-3 fine-tune purpose-built for authorized security testing |
| Red Team — mutation / planning | **Qwen3-32B** or DeepSeek-V3 | Strong agentic reasoning; structural, not refusal-prone |
| Judge — semantic-judgment cases | **Mistral-Large-2** or Foundation-Sec-8B | *Different family* from the Red Team → independent judge by design |
| Documentation | **Llama-3.1-8B-Instruct** | Templated markdown fill-in; cheap |

The deterministic floor (PyRIT + promptfoo + garak corpora + public datasets like HarmBench / JailbreakBench / AdvBench) runs on every cycle; the LLM is invoked only to mutate near-misses. This is more defensible than "we asked an LLM to be evil": reproducible, auditable, cheap, and not dependent on a single provider's refusal policy.

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
├── ARCHITECTURE.md           (TBD — multi-agent design + diagram)
├── THREAT_MODEL.md           (TBD — full attack-surface map)
├── USERS.md                  (TBD — who uses AgentForge, workflows, why automation)
├── presearch.md              (planning doc — constraints, decisions, open questions)
├── evals/
│   └── success_criteria.md   (the invariant table — Judge's spec)
├── src/agentforge/           (Python package)
├── tests/                    (pytest)
├── .github/workflows/        (CI + scheduled attack loops)
├── LICENSE                   (MIT)
└── pyproject.toml            (uv project)
```

## Run instructions

_Coming soon._ See [`presearch.md`](presearch.md) for the full plan; see [`evals/success_criteria.md`](evals/success_criteria.md) for what the platform actually checks.

## Roadmap (post-Friday)

1. Production-grade Judge corpus (200+ hand-adjudicated cases).
2. Langfuse trace integration for agent-level debugging.
3. Deeper PyRIT / garak / promptfoo coverage.
4. Plug-in for the openemr fork's CI to gate on AgentForge's regression suite.

## License

[MIT](LICENSE)
