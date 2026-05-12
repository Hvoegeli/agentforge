"""Tests for the Red Team agent + the seed attack corpus."""

from __future__ import annotations

import re
from typing import ClassVar

from agentforge.attacks.red_team import RedTeamAgent, context_from_case
from agentforge.attacks.seeds import SEEDS_BY_CATEGORY, is_canary, make_canary
from agentforge.models import AttackCase, TargetSurface, ThreatCategory


class TestCanary:
    def test_format_and_uniqueness(self) -> None:
        c1, c2 = make_canary(), make_canary()
        assert is_canary(c1) and is_canary(c2)
        assert c1 != c2
        assert re.fullmatch(r"AF-CANARY-[0-9a-f]{16}", c1)

    def test_is_canary_negative(self) -> None:
        assert not is_canary("hello")
        assert not is_canary("AF-CANARY")  # no trailing "-<hex>"


class TestSeedCorpus:
    REQUIRED_KEYS: ClassVar[set[str]] = {
        "subcategory",
        "surface",
        "turns",
        "expected_safe_behavior",
        "invariant_id",
        "framework_refs",
    }

    def test_every_seed_well_formed(self) -> None:
        for cat, seeds in SEEDS_BY_CATEGORY.items():
            assert seeds, f"category {cat} has no seeds"
            for seed in seeds:
                missing = self.REQUIRED_KEYS - seed.keys()
                assert not missing, f"{cat}/{seed.get('subcategory')} missing {missing}"
                assert isinstance(seed["turns"], list) and seed["turns"]
                assert isinstance(seed["surface"], TargetSurface)
                assert isinstance(seed["framework_refs"], list)

    def test_c1_has_indirect_and_multiturn_seeds(self) -> None:
        c1 = SEEDS_BY_CATEGORY["prompt_injection"]
        subs = {s["subcategory"] for s in c1}
        assert any("indirect" in s for s in subs)
        assert any(len(s["turns"]) > 1 for s in c1)


class TestRedTeamGenerate:
    def test_generates_valid_attack_cases_with_canaries(self) -> None:
        rt = RedTeamAgent()
        cases = rt.generate_attack_cases(ThreatCategory.PROMPT_INJECTION)
        assert cases
        for case in cases:
            assert isinstance(case, AttackCase)
            assert case.category is ThreatCategory.PROMPT_INJECTION
            for turn in case.prompt_or_sequence:
                assert "{canary}" not in turn
            ctx = context_from_case(case)
            assert "canary" in ctx and is_canary(ctx["canary"])
            assert "sentinel_tools" in ctx and isinstance(ctx["sentinel_tools"], list)

    def test_filters(self) -> None:
        rt = RedTeamAgent()
        single = rt.generate_attack_cases(ThreatCategory.PROMPT_INJECTION, include_multi_turn=False)
        assert single and all(len(c.prompt_or_sequence) == 1 for c in single)
        chat_only = rt.generate_attack_cases(
            ThreatCategory.PROMPT_INJECTION, surfaces={TargetSurface.CHAT}
        )
        assert chat_only and all(c.surface is TargetSurface.CHAT for c in chat_only)
        limited = rt.generate_attack_cases(ThreatCategory.PROMPT_INJECTION, limit=2)
        assert len(limited) <= 2

    def test_extra_subs_filled(self) -> None:
        rt = RedTeamAgent()
        cases = rt.generate_attack_cases(
            ThreatCategory.DATA_EXFILTRATION, extra_subs={"other_patient_name": "Doe"}
        )
        joined = " ".join(t for c in cases for t in c.prompt_or_sequence)
        assert "Doe" in joined
        assert "{other_patient_name}" not in joined


class TestRedTeamMutate:
    def test_mutate_produces_distinct_variants(self) -> None:
        rt = RedTeamAgent()
        original = rt.generate_attack_cases(ThreatCategory.PROMPT_INJECTION, limit=1)[0]
        variants = rt.mutate(original, n=4)
        assert 1 <= len(variants) <= 4
        orig_canary = context_from_case(original).get("canary")
        for v in variants:
            assert isinstance(v, AttackCase)
            assert v.id != original.id
            assert v.invariant_id == original.invariant_id
            assert v.prompt_or_sequence != original.prompt_or_sequence
            v_canary = context_from_case(v)["canary"]
            assert is_canary(v_canary) and v_canary != orig_canary
