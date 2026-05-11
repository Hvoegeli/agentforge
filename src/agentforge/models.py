"""Core data models for AgentForge.

These Pydantic models are the *contract* between the agents:

    Red Team Agent       -> produces AttackCase
    Target Adapter       -> produces AttackAttempt (executes an AttackCase vs the target)
    Judge Agent          -> produces JudgeVerdict (deterministic invariant check, or LLM-judge)
    Documentation Agent  -> produces Finding (and a markdown report)
    Orchestrator Agent   -> reads RunRecord + Finding + coverage to pick the next campaign

Every field the PRD's Stage-3 test-case checklist requires lives on ``AttackCase``
(category, subcategory, prompt/sequence, expected safe behaviour, observed behaviour,
severity, exploitability, regression-suite flag). The SQLite schema is one table per model.

Note: attack inputs and target responses are passed as *quoted data on structured
fields*, never as free-form context to a downstream agent — that is the prompt-injection
defence for AgentForge's own pipeline.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class ThreatCategory(StrEnum):
    """The six PRD attack categories (C1-C6) plus three bonus categories (B1-B3).

    Each maps to one or more OWASP Top-10-for-LLM-Apps-2025 IDs (see THREAT_MODEL.md).
    """

    PROMPT_INJECTION = "prompt_injection"  # C1 - OWASP LLM01 (+ LLM07)
    DATA_EXFILTRATION = "data_exfiltration"  # C2 - OWASP LLM02
    STATE_CORRUPTION = "state_corruption"  # C3 - OWASP LLM01 + LLM04 + LLM08
    TOOL_MISUSE = "tool_misuse"  # C4 - OWASP LLM06 (Excessive Agency)
    DENIAL_OF_SERVICE = "denial_of_service"  # C5 - OWASP LLM10 (Unbounded Consumption)
    IDENTITY_ROLE_EXPLOITATION = "identity_role"  # C6 - OWASP LLM06 + LLM01
    MISINFORMATION = "misinformation"  # B1 - OWASP LLM09 (the citation-guardrail category)
    IMPROPER_OUTPUT_HANDLING = "improper_output"  # B2 - OWASP LLM05
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"  # B3 - OWASP LLM07


class TargetSurface(StrEnum):
    """Where an attack lands on the target Co-Pilot."""

    CHAT = "chat"  # the /chat and /chat/stream endpoints
    DOCUMENT_UPLOAD = "document_upload"  # /api/upload -> rendered PNG pages -> vision model
    FHIR_FIELD = "fhir_field"  # instructions written into a Condition note / allergy comment / etc.
    CONVERSATION_HISTORY = "conversation_history"  # forged / replayed prior turns
    DASHBOARD_API = (
        "dashboard_api"  # /api/dashboard/patient/{pid}/*, /api/binary/{id}, /api/document-source/*
    )
    ADMIN_API = "admin_api"  # /api/admin/*
    RETRIEVAL_CORPUS = (
        "retrieval_corpus"  # the USPSTF/ADA guideline corpus behind retrieve_guidelines
    )


class AttackSource(StrEnum):
    """Where an attack case came from."""

    GARAK = "garak"  # NVIDIA garak probe
    PYRIT = "pyrit"  # Microsoft PyRIT orchestrator (incl. Crescendo / TAP)
    PROMPTFOO = "promptfoo"  # promptfoo OWASP-LLM-Top-10 plugin
    DATASET = "dataset"  # public corpus (HarmBench / JailbreakBench / AdvBench / PI sets)
    SEEDED_FINDING = (
        "seeded_finding"  # a known vulnerability we pre-loaded (zero-citation bypass, etc.)
    )
    LLM_MUTATION = "llm_mutation"  # the Red Team LLM mutated a near-miss into this variant
    HUMAN = "human"  # a human authored this case


class ObservedBehavior(StrEnum):
    """The Judge's verdict on an attempt."""

    PASS = "pass"  # the target behaved safely (the attack did NOT succeed)
    FAIL = "fail"  # the attack succeeded (an invariant was violated)
    PARTIAL = "partial"  # the attack partially succeeded / got close
    UNCERTAIN = "uncertain"  # the Judge could not adjudicate -> visible in coverage, escalates to human review


class CheckType(StrEnum):
    DETERMINISTIC = "deterministic"  # a machine-checkable invariant assertion (no LLM)
    LLM_JUDGE = "llm_judge"  # a semantic judgement by the (corpus-validated) LLM-Judge


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LEAD = "lead"  # a behaviour we cannot adjudicate via an invariant or corpus-validated judgement


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"  # fixed in the target + the regression replay holds
    LEAD = "lead"  # surfaced for human triage, not a confirmed finding
    REGRESSION = "regression"  # a previously-resolved finding has reappeared


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _new_id() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class AttackCase(BaseModel):
    """One adversarial test case. Carries every field the PRD Stage-3 checklist requires."""

    id: str = Field(default_factory=_new_id)
    category: ThreatCategory
    subcategory: str  # e.g. "indirect-injection-via-document-image"
    surface: TargetSurface
    prompt_or_sequence: list[str]  # one item = single-turn; many = a multi-turn sequence
    expected_safe_behavior: str  # what a safe target should do (the PRD's "expected safe behavior")
    invariant_id: str  # references evals/success_criteria.md (e.g. "C1.canary-or-sentinel")
    framework_refs: list[str] = Field(
        default_factory=list
    )  # e.g. ["OWASP-LLM01", "ATLAS-AML.T0051", "NIST-AI600-1:InfoSec"]
    source: AttackSource
    in_regression_suite: bool = False  # promoted only after a confirmed/approved finding
    severity_hint: Severity | None = (
        None  # the Red Team's a-priori guess; the Finding carries the real one
    )
    notes: str = ""
    created_at: datetime = Field(default_factory=_now)


class ToolCallTrace(BaseModel):
    """One tool invocation observed in the target's response trace."""

    name: str
    args_redacted: dict[str, str] = Field(default_factory=dict)
    ok: bool
    latency_ms: float | None = None
    error: str | None = None


class AttackAttempt(BaseModel):
    """The result of executing one AttackCase against the target at a pinned SHA."""

    id: str = Field(default_factory=_new_id)
    attack_case_id: str
    target_sha: str  # which Co-Pilot commit was attacked
    target_base_url: str  # local docker stack vs deployed Hetzner instance
    request_summary: str  # sanitised description of what was sent
    response_redacted: str  # the target's response, run through the PHI redactor
    tool_trace: list[ToolCallTrace] = Field(default_factory=list)
    token_usage: dict[str, int] = Field(default_factory=dict)  # {"input": ..., "output": ..., ...}
    cost_usd: float = 0.0
    latency_ms: float | None = None
    n_supervisor_hops: int | None = None  # for the DoS / recursion invariants
    error: str | None = None  # "timeout" / "target_unavailable" / "provider_error" / ...
    executed_at: datetime = Field(default_factory=_now)


class JudgeVerdict(BaseModel):
    """The Judge's adjudication of one AttackAttempt. Independent of the attack engine."""

    id: str = Field(default_factory=_new_id)
    attack_attempt_id: str
    check_type: CheckType
    observed_behavior: ObservedBehavior
    invariant_passed: bool | None = None  # set for deterministic checks; None for llm_judge-only
    confidence: float | None = None  # set for llm_judge (0..1); None for deterministic
    rationale: str  # why the Judge ruled this way (cites the invariant / the evidence)
    evidence_links: list[str] = Field(
        default_factory=list
    )  # pointers into the trace / response that justify the verdict
    judge_model: str | None = None  # which model rendered the verdict (None for pure-deterministic)
    judge_prompt_version: str | None = (
        None  # so a verdict can be re-validated when the Judge prompt changes
    )
    judged_at: datetime = Field(default_factory=_now)


class Finding(BaseModel):
    """A confirmed (or human-approved) vulnerability, ready to become a vuln report + a regression case."""

    id: str = Field(default_factory=_new_id)
    attack_case_id: str
    attack_attempt_id: str
    judge_verdict_id: str
    category: ThreatCategory
    severity: Severity
    exploitability: str  # the PRD's "exploitability assessment"
    clinical_impact: str  # what this means for a clinician / a patient
    framework_mapping: list[str] = Field(
        default_factory=list
    )  # OWASP / ATLAS / NIST refs for the vuln report
    evidence_links: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    human_approved: bool = False  # required before a CRITICAL report is filed (the trust gate)
    report_path: str | None = None  # path to the generated vuln report markdown, once written
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


class RunRecord(BaseModel):
    """One Orchestrator-driven campaign run — the unit of cost/coverage accounting."""

    id: str = Field(default_factory=_new_id)
    orchestrator_directive: (
        str  # e.g. "probe under-tested category C2 against local target, budget $0.40"
    )
    categories_targeted: list[ThreatCategory] = Field(default_factory=list)
    target_sha: str
    target_base_url: str
    n_attacks: int = 0
    n_confirmed_findings: int = 0
    n_uncertain: int = 0
    total_cost_usd: float = 0.0
    halted_reason: str | None = (
        None  # "budget_reached" / "no_signal" / "target_unavailable" / "human_stop" / None
    )
    started_at: datetime = Field(default_factory=_now)
    finished_at: datetime | None = None
