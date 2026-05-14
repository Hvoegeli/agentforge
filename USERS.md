# USERS.md — Who AgentForge Is For

_AgentForge ([`Hvoegeli/agentforge`](https://github.com/Hvoegeli/agentforge)) is a standalone adversarial-evaluation platform. The target it attacks — the Clinical Co-Pilot — is a different repo ([`Hvoegeli/openemr`](https://github.com/Hvoegeli/openemr)); paths like `clinical-copilot/evals/` in this file point inside that repo, not this one. See [`MVP_EVIDENCE.md`](MVP_EVIDENCE.md) for the runnable cross-process proof._

_Companion docs: [`THREAT_MODEL.md`](THREAT_MODEL.md) (the attack surface), [`ARCHITECTURE.md`](ARCHITECTURE.md) (the multi-agent design), [`evals/success_criteria.md`](evals/success_criteria.md) (the invariants), [`presearch.md`](presearch.md) (constraints + decisions)._

---

## In one line

AgentForge is for the people responsible for whether a clinic can trust an AI-assisted clinical workflow — and for the engineer who has to keep that AI from regressing every time it changes. It is **not** a chatbot, **not** a clinical decision-support tool, and **not** something a clinician ever touches.

---

## The three users

### 1. The AI-security engineer (the operator)
**Who.** The person who runs AgentForge — a security engineer or AI-safety practitioner doing authorized adversarial evaluation of the Clinical Co-Pilot.

**Their goal.** Continuous, measured adversarial coverage of the Co-Pilot — not a one-time penetration test that goes stale the moment it's filed.

**Their workflow with AgentForge.**
- Starts an authorized, budgeted run from the dashboard (which target, which categories, what dollar/token ceiling). Watches it on the dashboard; can hit the **STOP button** at any time.
- Reviews the findings the Judge confirmed; approves CRITICAL vulnerability reports before they're filed; works the human-review queue for `UNCERTAIN` verdicts.
- Tunes the Judge: when a verdict was wrong, the corrected case goes into the labeled corpus (`evals/judge_corpus/`), the Judge prompt is re-tuned, and CI re-validates the agreement rate.
- Adds new attack categories / new corpus seeds (`evals/success_criteria.md` defines the invariant; PyRIT / promptfoo / garak / public datasets supply the seeds).
- Approves which confirmed findings get promoted into the regression suite that gates the Co-Pilot's own CI.

**Their use cases** (mapped to the threat model):
- *"Catch a new prompt-injection variant before it ships."* — C1. The Red Team mutates a near-miss into a working indirect-injection-via-document attack; the Judge confirms it deterministically (canary); a HIGH report files automatically.
- *"Prove the cross-patient ACL holds."* — C2. 100 cross-patient probes run; 0 succeed; the dashboard says so. A *negative result is a result.*
- *"Find the resource-amplification footgun."* — C5. A single crafted turn blows past the token/cost/wall-time thresholds; the meter trips the invariant; the Documentation agent writes it up with the exact numbers.

**Why automation, not a person doing this by hand:** see §"Why automation is the right solution" below.

### 2. The Co-Pilot maintainer (the consumer of findings)
**Who.** The engineer who builds and maintains the Clinical Co-Pilot (in this project, the same person wearing the other hat — but in general, a different role).

**Their goal.** Know *immediately* whether a change to the Co-Pilot reopened a known vulnerability or introduced a new regression — before it reaches a clinic.

**Their workflow with AgentForge.**
- Receives vulnerability reports that a senior engineer who wasn't present could reproduce, validate, and fix (unique ID, severity, clinical impact, minimal repro, observed vs expected, remediation grounded in NCSC ML principles / CSA AICM controls, fix-validation status).
- Patches the Co-Pilot; pushes; AgentForge detects the new git SHA, triggers the regression suite, and reports — for each previously-confirmed exploit — whether the invariant now holds across `N` replays (an honest confidence interval, not a binary PASS/FAIL, because the target is nondeterministic).
- Relies on AgentForge's regression suite (published as a release artifact, pulled cross-repo into the Co-Pilot's `clinical-copilot/evals/` gate) to block a build that re-broke a fixed vuln — but only after a human approved that gate, because a regression test that wrongly fails the Co-Pilot's build is worse than no test.

**Their use cases:**
- *"Did my citation-validator change reopen the zero-citation bypass?"* — B1 regression replay says yes/no, with the clear rate.
- *"Did fixing the document-image-injection gap break anything else?"* — the Suite flags cross-category regressions (a fix for X that turns Y from PASS to FAIL).
- *"Is the Co-Pilot getting more resilient over time?"* — the dashboard's resilience trend line, by category, by target SHA.

### 3. The compliance / security-governance reviewer (the "hospital CISO" persona)
**Who.** The person deciding whether to trust the Co-Pilot with systems physicians depend on — a CISO, a clinical-informatics security lead, a regulator-facing risk officer.

**Their goal.** Evidence that the Co-Pilot is being stress-tested the way any system clinicians depend on would be — *continuously*, with *measured* coverage, with an *audit trail*, against *named, published* threat frameworks — not a slide deck and a one-off jailbreak demo.

**Their workflow with AgentForge.**
- Reads the dashboard: category coverage and per-category attempt counts; pass / fail / partial / uncertain rates by category and target SHA; the resilience trend; findings by severity (open / in-progress / resolved); the Judge's *measured* agreement rate; cost by run / category / agent / model / provider.
- Reads the vulnerability reports: each one carries OWASP / MITRE ATLAS / NIST AI RMF references and a clinical-impact statement, so it slots into an existing risk register.
- Reads the audit log: every Orchestrator decision, Red Team attack, Judge verdict, Documentation generation, and target request, with timestamps — "what happened during last night's run?" is answerable.
- Sees the responsible-testing posture stated up front (`THREAT_MODEL.md` §8): authorized scope, synthetic data only, allowlisted target, rate caps, transcript redaction, no autonomous remediation, human approval on critical findings, AgentForge's own agents hardened against prompt injection.

**Their use case:** *"Before physicians depend on this AI, show me the test program."* — AgentForge *is* the test program, and it's legible: framework-mapped, continuous, audited, with a measured judge and an honest "here's what we couldn't break, and here's the proof we tried."

### (Roadmap) The BYO-target operator
Not a v0 user. Once the threat-model schema (`evals/success_criteria.md`) and the attack corpus are factored out from the Co-Pilot specifics, AgentForge could point at any FHIR-backed (or any HTTP-reachable) LLM application. Mentioned here because the architecture already separates the Target Adapter from everything else — but it is explicitly out of scope for the Week-3 deliverable.

---

## Why automation is the right solution

The PRD is blunt about it: *"The concern is not whether a single exploit exists. The concern is whether the system can continuously identify, evaluate, and defend against new attack techniques as the platform evolves."* That is, by definition, a continuous, autonomous job. A human doing manual prompting and keeping a static attack list cannot do it, for four concrete reasons:

1. **Attacks mutate; a static suite is stale the moment it ships.** Defenses built around a handful of known payloads rarely hold once attackers (or model updates, or new published techniques) shift the phrasing. Generating *the variant that breaks through* — taking a partially-successful attack and producing ten mutations of it — is a generation problem, not a lookup. The Red Team agent does this within a budget; a person does it slowly and inconsistently. *(But the floor is still a curated corpus — PyRIT / garak / promptfoo / HarmBench / JailbreakBench / AdvBench — so the deterministic part stays reproducible and auditable.)*

2. **"Which category is least-tested right now?" is a continuous optimization problem.** Given everything that's happened — attempt counts per category, open high-severity findings, recent regressions, spend-so-far — the next campaign should target the gap with the highest expected signal. A person can't hold that state in their head across runs; the Orchestrator reads it from the observability DB every cycle and decides.

3. **Regression-on-every-deploy is impossible by hand at software cadence.** Software changes daily; re-running every confirmed exploit on every change, `N` times each, asserting the *invariant* not the output string, and flagging cross-category regressions — that's a `pytest` job triggered by a git-SHA change, not a human task.

4. **A pentest is a snapshot; trust requires a trend.** "It was secure when we tested it in March" is not what a clinic needs. A continuously-running, measured program that says "C2 has held across 5 weeks and 800 cross-patient probes; C1 regressed last Tuesday and was fixed Wednesday; the Judge agrees with human ground truth 94% of the time" — *that* is what makes the AI trustworthy to someone accountable for it.

### And why automation is *not* the whole answer

Automation has a trust problem of its own: an agent that confidently files a false-positive wastes engineering time, and an agent that could push fixes or trigger workflows without review could introduce new vulnerabilities. So AgentForge keeps the human in the loop *exactly where judgment matters*, and only there:

- **Critical findings** are held as drafts pending human approval — nothing CRITICAL is auto-filed.
- **Uncertain verdicts** route to a human-review queue, visible in coverage metrics — never silently treated as pass or fail.
- **Gating the Co-Pilot's CI** with a regression case requires explicit human sign-off.
- **The STOP button** on the dashboard halts any run mid-flight.
- **AgentForge never remediates** — it documents; it does not patch the target, open tickets, or trigger workflows.

The design principle: *remove the human from the parts a human can't keep up with (mutating attacks, tracking coverage, replaying regressions on every deploy); keep the human in the parts where being wrong is expensive (filing a CRITICAL report, overriding an uncertain verdict, blocking a production build).*

---

## Out of scope (non-users)

- **Clinicians / patients** — never interact with AgentForge. The *target* (the Co-Pilot) is the clinician-facing surface; AgentForge attacks it.
- **General-purpose penetration testers** — AgentForge is not a generic pentest framework; it tests one allowlisted target against an LLM-application threat model. (Generalization is a roadmap item, not the product.)
- **The Co-Pilot's end users** — AgentForge produces no clinical output, makes no clinical recommendations, and touches no real patient data (synthetic only).
