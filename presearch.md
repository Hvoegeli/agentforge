# Presearch — AgentForge

_Date: 2026-05-11 (Mon, MST)_
_Stage: production-quality (graded demo to a hospital CISO; public repo; deployed dashboard)_
_Architecture-defense checkpoint: 2026-05-11 ~PM MST · MVP: Tue 2026-05-12 11:59 PM · Final: Fri 2026-05-15 noon_

---

## Phase 1: Constraints

### 1. Domain Selection
- **Domain.** Custom — autonomous adversarial AI security evaluation of a healthcare LLM application. The target is the OpenEMR Clinical Co-Pilot (FastAPI + LangGraph chatbot over FHIR patient data, built Weeks 1–2, deployed on Hetzner).
- **Use cases.**
  - Continuous red-teaming of the deployed Co-Pilot (Red Team agent generates + mutates attacks; Orchestrator picks coverage gaps; Judge verdicts; Documentation produces vuln reports).
  - Discovery and confirmation of new vulnerabilities.
  - Regression validation — every confirmed exploit becomes a deterministic test that re-runs on every target SHA.
  - Cost / coverage / resilience trend reporting over time.
  - Cross-repo: confirmed exploits published as release artifacts the Co-Pilot's `clinical-copilot/evals/` gate can pull in.
- **Verification requirements.**
  - Deterministic invariants (machine-checkable assertions) per threat category, captured in `evals/success_criteria.md`.
  - For categories that genuinely need semantic judgment, an LLM-Judge validated against a labeled ground-truth corpus (~30–50 hand-adjudicated transcripts), with a measured agreement / FP / FN rate re-run on every Judge-prompt change.
  - Mappings to established taxonomies: OWASP Top 10 for LLM Applications 2025, MITRE ATLAS, NIST AI 600-1 (Generative AI Profile), OWASP Agentic-AI / Multi-Agentic System Threat Modeling Guide.
  - Reproducible attack replays — every finding stored with a deterministic conversation prefix and the target SHA at time of capture.
- **Data sources.**
  - **Target data:** Synthetic FHIR data only (OpenEMR demo patients) on the existing Hetzner-deployed Co-Pilot.
  - **Attack corpus seeds:** OWASP LLM-Top-10 plugins via promptfoo; garak probes; PyRIT multi-turn orchestrators (Crescendo, TAP); public datasets (HarmBench, JailbreakBench, AdvBench, prompt-injection corpora).
  - **Standards docs:** OWASP (`genai.owasp.org`), MITRE ATLAS (`atlas.mitre.org`), NIST AI 600-1.

### 2. Scale & Performance
- **Query volume.**
  - Dev: ~100–200 attack runs over the week (constrained by $10–50 budget).
  - Cost analysis: 100 runs **measured**; 1K / 10K / 100K **projected** from measured data with stated methodology (PRD explicitly says "not cost-per-token × n").
  - Hourly scheduled run during demo week (Wed–Fri); daily after.
- **Latency.** Not real-time. Per-attack: 10–60 s typical; hard timeout **120 s single-turn / 300 s multi-turn**. Demo loop fits in 3–5 min recorded video.
- **Concurrency vs. target.** 1–3 concurrent at most. Target = existing Hetzner Co-Pilot (~3.7 GB RAM, real OOM risk under load). **Rate cap: ~20 attacks/min (1 every 3 s)** — Orchestrator-owned.
- **Cost constraints.** Hard cap: $10–50 for the full Mon–Fri sprint. OpenRouter API key spend cap: $5/day during dev. Per-run: $0.01–0.04. Judge corpus rerun: ~50 × ~$0.01 = ~$0.50; ~5 reruns over the week = ~$2.50.

### 3. Reliability Requirements
- **Cost of a wrong answer.**
  - False-positive Judge (says attack succeeded when it didn't) → wastes review time; erodes CISO trust; trains the team to ignore alerts.
  - False-negative Judge (misses a real exploit) → the platform's reason for being. A missed vuln in production is a clinical-safety surface.
  - These are why the Judge corpus + measured agreement rate is the load-bearing artifact.
- **Verification non-negotiable.**
  - Invariant-first verdicts.
  - Pinned Co-Pilot git SHA for the regression baseline (recorded in `THREAT_MODEL.md`).
  - Labeled Judge corpus with measured agreement rate (re-measured on every Judge-prompt change).
  - N-replays-with-clear-rate transparency (honest confidence interval, not "PASS/FAIL").
- **Human-in-the-loop.**
  - Critical-severity finding before formal report file → human approval.
  - Judge confidence < 0.7 on semantic-judgment cases → human review queue.
  - Judge confidence < 0.5 → stored as "lead", not "finding".
- **Audit / compliance.**
  - AgentForge itself: full SQLite + JSONL audit log of every Orchestrator decision, Red Team attack, Judge verdict, Documentation generation, and HTTP request to the target.
  - "Imagined production use": full audit log + retention; framed as future work in README.
  - Target: synthetic data only; rate-limited; transcripts redacted before storage.

### 4. Team & Skill Constraints
- **Solo developer.** Harrison Voegeli.
- **Agent framework familiarity.** Competent — just shipped W1/W2 Co-Pilot in LangGraph (supervisor + workers + answerer topology, citation validator, in-process trace store).
- **Domain experience (security / pentesting).** **None — brand new.** Implications: the docs do the heavy lifting (define every OWASP/ATLAS reference inline; glossary section in THREAT_MODEL.md; vuln reports readable by someone learning the field). The defense relies on the docs explaining the work, not extemporaneous verbal answers.
- **Eval / testing frameworks.** Competent — shipped PR-blocking eval gate + snapshot-replay harness in W1/W2.

---

## Phase 2: Architecture Discovery

### 5. Agent Framework Selection
- **Framework: LangGraph.** Stack consistency with W1/W2; supervisor pattern with state-as-DB hand-off; one graph, four agent nodes + the regression harness + the observability DB.
- **Topology:** Multi-agent, supervisor-style. Orchestrator = router node. Red Team / Judge / Documentation = agent nodes. State = SQLite findings/coverage table (which IS the observability layer).
- **State management:** SQLite for durable findings/coverage; per-turn graph state via LangGraph's built-in state machine.
- **Tool integration:** Medium. The Red Team Agent wraps PyRIT + promptfoo (+ optionally garak); the rest are pure LLM nodes. PyRIT defaults to Azure OpenAI — config override needed to point it at OpenRouter's OpenAI-compatible endpoint.

### 6. LLM Selection
- **Constraint:** No main-LLM proprietary APIs (no Anthropic / OpenAI / Google direct).
- **Provider:** **OpenRouter primary** (one API key, one OpenAI-compatible endpoint, model fallback chains, ~5–10% markup over underlying provider). **Together AI as secondary** for direct access to workhorse open-weights if OpenRouter is degraded.
- **Model split:**

  | Role | Recommended | Fallback | Why |
  |---|---|---|---|
  | Red Team — attack generation | **WhiteRabbitNeo-2-70B** (Llama-3 fine-tune purpose-built for authorized security testing) | Dolphin-3-Llama-70B (abliterated general) | Security-specialty open-weight; defensible CISO story; will produce payloads under authorized framing |
  | Red Team — mutation / planning | **Qwen3-32B** or **DeepSeek-V3** | Llama-3.3-70B-Instruct | Structural reasoning; JSON-mode adherence; not the refusal-prone surface |
  | Judge — semantic-judgment cases | **Mistral-Large-2** or **Foundation-Sec-8B** | Qwen3-32B with strict rubric prompt | Different family from Red Team → real model diversity → independent judge |
  | Documentation | **Llama-3.1-8B-Instruct** | Any cheap 7-8B | Templated markdown fill-in |

- **Function calling:** All support tool/JSON modes via OpenRouter's OpenAI-compatible endpoint. WhiteRabbitNeo less consistent — fine, it's the attack-generation model, not the planner.
- **Context window:** Sufficient (each agent works on a small slice of state).
- **Cost per query:** $0.01–0.04 typical attack run; Documentation < $0.005.
- **Model abstraction:** OpenRouter SDK in-process (simpler than LiteLLM since we're all-OpenRouter primary).

### 7. Tool Design
- **AgentForge's tools (what the agents call):**
  - **PyRIT** (multi-turn Crescendo / TAP orchestrators) — wrapped as the deterministic attack engine.
  - **promptfoo** (YAML-driven, OWASP-LLM-Top-10 built-in plugins) — wrapped for the per-cycle deterministic floor runs.
  - **garak** (NVIDIA, 37+ probe modules) — optional, add if time.
  - **HTTP client** → Co-Pilot's chat / upload / dashboard / admin endpoints. The "target" is reached over HTTP exactly as an external attacker would.
  - **SQLite findings store** + JSONL trace writer.
  - **Invariant-checker library** (deterministic assertions per category, defined in `evals/success_criteria.md`).
- **Dev environments (tiered):**
  - **Unit tests:** Co-Pilot mocked with Python fixtures (instant, free).
  - **Integration loop:** Local docker stack of the Co-Pilot via `clinical-copilot/docker/development-easy` (already working from W1/W2 dev).
  - **Live runs / demo / scheduled CI:** The existing Hetzner-deployed Co-Pilot (per user decision — no separate staging instance for MVP).
- **Error handling:** Per-run timeouts (120 s single-turn / 300 s multi-turn); OpenRouter fallback chain on model 502s; target `/healthz` ping before each batch with halt-and-surface if target is down.

### 8. Observability Strategy
- **Approach:** Skip hosted service this week. Build the cheap layer that satisfies the 6 PRD-required questions:
  - **SQLite findings DB** (categories tested + counts; open/in-progress/resolved; pass/fail by category + version; resilience trend; cost; per-agent activity).
  - **JSONL trace log** (one line per Orchestrator decision / Red Team attack / Judge verdict / Doc generation).
  - **Static HTML dashboard** rendered from SQLite by the GitHub Action and deployed to the read-mostly URL.
- **Metrics that matter:** Per-category pass/fail rate over time; Judge agreement rate (load-bearing); cost-per-run + cost-per-confirmed-finding; rate-limited attack throughput; resilience trend by target SHA.
- **Cost tracking:** Per-agent, per-run, per-category in SQLite. Cost-without-signal kill switch: Orchestrator halts a category after $0.50 spent without a confirmed finding.
- **Future (post-Friday):** Add **Langfuse** (open-source, free tier) if debug-time becomes painful.

### 9. Eval Approach
- **Correctness measurement.**
  - "Platform is correct" = Judge verdicts match human ground truth on a labeled corpus.
  - Per-category pass/fail measurement = the regression replays over time at fixed target SHAs.
- **Ground truth.** Manually adjudicated Judge corpus of ~30–50 attack transcripts (~half successful, ~half not). Built early in MVP-Tue. Labels documented in `evals/judge_corpus/<case_id>.yaml` with the verdict, the rationale, and the invariant that was checked.
- **Automated vs human.**
  - Automated: invariant checks (deterministic); LLM-Judge on semantic-judgment cases; regression replays.
  - Human: ground-truth labeling (one-time per case + on additions); critical-severity finding approval before formal report file.
- **CI integration.**
  - Judge-corpus replay on every push that touches a Judge prompt (~$0.50/run, fast).
  - Hourly scheduled attack runs Wed–Fri against the live Co-Pilot, results committed back as artifacts.

### 10. Verification Design
- **What must be verified:** Every finding asserts an invariant from `evals/success_criteria.md`. Critical-severity additionally requires human approval before report-file.
- **Fact-checking data sources:** The target's tool-call trace + the response transcript + the panel ACL state at request time (all captured by AgentForge's HTTP layer).
- **Confidence thresholds.**
  - Deterministic invariant: yes/no — no confidence value.
  - LLM-Judge: ≥ 0.7 → finding; 0.5–0.7 → human review queue; < 0.5 → stored as "lead", not "finding".
- **Escalation triggers.**
  - Critical severity → human approval gate before report file.
  - Repeated category failures (≥ 3 confirmed in 24 h) → Orchestrator escalates to "high priority" and runs more variants.
  - Cost-without-signal → Orchestrator halts category.

---

## Phase 3: Post-Stack Refinement

### 11. Failure Mode Analysis
- **Tool fails.**
  - LLM provider 502 → OpenRouter falls back to next model in chain. If all fail → mark "provider unavailable", skip run, surface on dashboard.
  - PyRIT/promptfoo Python exception → wrap with try/except, mark "tool error", continue.
  - Target HTTP 5xx → ping `/healthz`, if down halt the batch and surface "target unavailable".
- **Rate limiting.** Orchestrator-owned cap of ~20 attacks/min (1 every 3 s). OpenRouter has its own rate limits; on 429, exponential backoff.
- **Graceful degradation.**
  - WhiteRabbitNeo refuses → fallback to Dolphin-3 (OpenRouter fallback chain).
  - Judge model temporary failure → queue verdict, retry next batch (don't lose attack-side trace).
  - Cost ceiling approached → Orchestrator switches to deterministic-only attacks (no LLM mutation).

### 12. Security Considerations
- **Prompt injection of AgentForge's own agents.** Judge sees only `{attack_input, target_output, category, invariant}` as structured fields, never as free-form context. Documentation Agent reads attack strings from a `raw_attack:` JSON field. Output schema validation between agents.
- **Data leakage.** Synthetic data only on the target. Even so, transcripts redacted via a `safe_log.py`-pattern redactor (names, MRNs, DOBs, phones, SSNs) before storage. Trace store does not include raw LLM payloads beyond the redacted transcript.
- **API key management.** OpenRouter key in **GitHub Secrets** (CI) + local `.env` (dev, gitignored). Deployed dashboard does not call LLMs and does not need the key.
- **Audit logging.** Every Orchestrator decision, Red Team attack, Judge verdict, Documentation generation, and HTTP request to the target written to SQLite + JSONL.
- **Dashboard auth.** HTTP basic auth, single shared demo password (documented in README; OAuth-via-GitHub is the production upgrade path).
- **Target exposure.** Existing Hetzner Co-Pilot deployment (per user decision). AgentForge's HTTP client uses the same auth path as a legitimate user. Rate cap from AgentForge side, plus the Co-Pilot's own per-user session model.

### 13. Testing Strategy
- **Unit tests.** Invariant-checker library (~10 cases derived from `evals/success_criteria.md` — one per category invariant). Pytest.
- **Integration tests.** Each LangGraph node with mocked LLM responses (pytest + recorded fixtures). One end-to-end test through the full closed loop against a mocked Co-Pilot.
- **Adversarial testing.** This *is* the product — the system is one big adversarial test of the Co-Pilot. Internal adversarial: prompt-injection-of-AgentForge protections (the structured-field defense in §12).
- **Regression testing.** Every confirmed exploit stored as a deterministic replay. Re-runs on every target-SHA bump; N replays with clear-rate reporting.
- **CI.** Tests run on every push to the AgentForge repo. Hourly scheduled attack runs against the live Co-Pilot during demo week (Wed–Fri).

### 14. Open Source Planning
- **Release.** Full AgentForge repo at MVP submission (Tue) and Final (Fri). Plus three vuln reports + the cost analysis + the architecture diagram.
- **License: MIT.** Standard for security tooling (PyRIT is MIT, promptfoo MIT, garak Apache-2). Zero-friction adoption.
- **Repos.** Public GitHub primary + GitLab mirror for redundancy.
- **Documentation.** README + ARCHITECTURE.md (+ diagram) + THREAT_MODEL.md + USERS.md + vuln reports + cost analysis + `evals/` directory (success_criteria.md + judge corpus + thresholds).
- **Community engagement.** Social post on Fri tagging @GauntletAI from @HarrisonVoegeli. README "Roadmap" section indicates direction; no commitment to maintain.

### 15. Deployment & Operations
- **Hosting.** Dashboard on **Fly.io** (free tier) by default. Alternative: a tiny **Hetzner CX11** ($4/mo, familiar platform). Fly.io picked to minimize ops time this week.
- **CI/CD.** GitHub Actions primary, GitLab mirror. On every push: run tests + (if it's a Judge prompt change) replay the corpus. Scheduled: hourly attack runs Wed–Fri, then daily.
- **Monitoring / alerting.** Skip for MVP — the dashboard IS the alert surface. Future work: email/Slack notifier on critical findings.
- **Rollback.** AgentForge is stateless except for SQLite findings DB; rollback = revert deploy + (optionally) restore previous SQLite snapshot. SQLite committed to the repo on every CI run so history is reconstructable.

### 16. Iteration Planning
- **Feedback.** Developer-driven this week. Post-Friday: open repo, accept issues, optional blog post.
- **Eval-driven cycle.** Judge agreement rate is the headline metric. Drop in agreement → freeze Judge prompt + investigate. Categories with consistently low FP rate → consider expanding to more attack variants.
- **Feature prioritization.** Council 2's cut-list applies (Orchestrator intelligence → priority queue; multi-turn → single-turn; hosted observability → defer).
- **Long-term maintenance.** Portfolio piece. Roadmap in README: (1) Production-grade Judge corpus 200+ cases; (2) Langfuse trace integration; (3) Deeper PyRIT/garak/promptfoo coverage; (4) Plug-in for the openemr fork's CI to gate on AgentForge's regression suite.

---

## Open questions / unresolved

- **Verify the Co-Pilot dashboard / binary / document-source endpoints carry the same panel ACL** as the chat tools (`/api/dashboard/patient/{pid}/*`, `/api/binary/{id}`, `/api/document-source/{type}/{id}`). If not → Day-One C2 IDOR finding. Open item #1 in `evals/success_criteria.md`.
- **Verify whether the Co-Pilot chat endpoints accept client-supplied conversation history.** If yes → C3's forged-history invariant has a direct exploit path.
- **Verify the Co-Pilot's worker→tools loop iteration bound.** Feeds C5's `N` threshold.
- **Pin the Co-Pilot git SHA** at MVP-Tuesday for the regression baseline. Record in `THREAT_MODEL.md`.
- **Fill `evals/thresholds.yaml`** (T tokens / $C cost / S seconds / N iterations / k amplification) from `clinical-copilot/COST_LATENCY_REPORT.md` p95 figures.
- **Will the user patch ≥ 1 Co-Pilot exploit Wed–Thu?** Affects whether vuln reports have "fix validation results" (PRD requirement). If not, vuln reports note "status: open, fix planned" honestly. User position so far: "perhaps, after I'm happy with AgentForge."
- **Confirm PRD interpretation on live-target requirement at MVP.** Council reading + PRD Stage-3 HARD GATE: live tests against the deployed target required for both early and final submissions. User has stated the existing Hetzner Co-Pilot satisfies this — no new staging instance. If the user meant "no live attacks at all on Tuesday," the HARD GATE would be missed.

---

## Decisions locked in (Mon 2026-05-11)

- **4 agents** in LangGraph: Red Team, Judge, Orchestrator, Documentation. No 5th. Maps 1:1 to PRD required roles.
- **Separate repo** on GitHub + GitLab (mirrored). License **MIT**.
- **No main LLMs.** OpenRouter primary, Together secondary. WhiteRabbitNeo for attack-gen, Qwen3-32B/DeepSeek for mutation, Mistral-Large-2/Foundation-Sec-8B for Judge, Llama-3.1-8B for Documentation.
- **Wrap PyRIT** (multi-turn) + **promptfoo** (OWASP-LLM-Top-10 plugins) as the deterministic attack engine. garak optional. Public seed datasets (HarmBench, JailbreakBench, AdvBench, PI corpora). Deterministic floor every cycle; LLM mutation only on near-misses.
- **Deterministic invariants** for Judge verdicts where possible (per `evals/success_criteria.md`); **LLM-Judge** validated against a ~30–50 case ground-truth corpus for semantic-judgment cases; agreement rate measured and re-measured on every Judge-prompt change. Threshold: ≥0.7 → finding; 0.5–0.7 → human review; <0.5 → lead-only.
- **SQLite findings DB + JSONL trace log + static HTML dashboard** from CI. Skip hosted observability service this week.
- **Deployed URL: read-mostly observability dashboard with basic auth.** Attack execution from GitHub Actions, NOT from the URL.
- **Target: existing Hetzner-deployed Co-Pilot** (user decision — no new staging instance for MVP). Rate cap 20 attacks/min from AgentForge side. Synthetic patients only. Transcripts redacted before storage.
- **Standards spine:** OWASP LLM Top 10 2025 + MITRE ATLAS + NIST AI 600-1; multi-agent threats via OWASP Agentic-AI / Multi-Agentic Threat Modeling Guide. Operationalize known taxonomies; do not invent new ones.
- **Cost discipline:** $10–50 ceiling for the week. OpenRouter spend cap $5/day. Cost-without-signal kill switch at $0.50/category. **Cost analysis: ~100 runs measured; 1K/10K/100K projected** with stated methodology (per PRD "not cost-per-token × n").
- **Per-run timeouts:** 120 s single-turn / 300 s multi-turn (hard kill, mark "timeout", move on).
- **Human-in-the-loop gates:** critical-severity findings require human approval before report file.
- **Agent isolation:** Judge sees only `{attack_input, target_output, category, invariant}` — structured fields, no free-form Red Team context. Documentation reads `raw_attack:` as a JSON field. Output schema validation between agents (prompt-injection-of-AgentForge defense).
- **Reuse Co-Pilot's PHI redactor** (`safe_log.py`) for transcript redaction (forward-compat with non-synthetic data + good demo optics).
- **Demo recording:** record a successful end-to-end run early (Tue/Wed) as the canonical demo video. Optional live demo on top.
