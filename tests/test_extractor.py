import pytest

from smt_completeness.extractor import _extract_with_llm, load_offline_ir, self_check, extract
from smt_completeness.ir import Rule, RuleKind, Priority, Condition, Policy, Provenance
from smt_completeness.vocab import Decision


def test_offline_ir_loads_and_passes_self_check():
    p = load_offline_ir()
    assert len(p.rules) == 24
    rep = self_check(p)
    assert rep.ok is True
    assert rep.id_unique is True
    assert rep.vacuous_rule_ids == []


def test_self_check_rejects_empty_policy():
    rep = self_check(Policy(rules=[]))
    assert rep.ok is False
    assert rep.total_rules == 0


def test_self_check_detects_match_tautology():
    r = Rule.model_construct(
        id="T",
        source_anchor="没有已有策略完整匹配时进入兜底",
        kind=RuleKind.MUST_CHALLENGE,
        condition=Condition(),
        decision=Decision.CHALLENGE,
        priority=Priority.MANDATORY,
        extraction_confidence="high",
        reviewer_status="auto_approved",
        provenance=Provenance.EXTRACTED,
    )
    rep = self_check(Policy.model_construct(rules=[r]))
    assert "T" in rep.tautology_rule_ids
    assert rep.ok is False


def test_self_check_detects_duplicate_id():
    r = Rule(id="X", source_anchor="s", kind=RuleKind.MANDATORY_DENY,
             condition=Condition(flag_true=["destructive"]),
             decision=Decision.DENY, priority=Priority.MANDATORY,
             extraction_confidence="high")
    p = Policy(rules=[r, r.model_copy()])
    rep = self_check(p)
    assert rep.id_unique is False
    assert rep.duplicate_ids == ["X"]


def test_self_check_detects_vacuous_rule():
    r = Rule(id="V", source_anchor="s", kind=RuleKind.MANDATORY_DENY,
             condition=Condition(flag_true=["destructive"],
                                 flag_false=["destructive"]),
             decision=Decision.DENY, priority=Priority.MANDATORY,
             extraction_confidence="high")
    p = Policy(rules=[r])
    rep = self_check(p)
    assert "V" in rep.vacuous_rule_ids
    assert rep.ok is False


def test_extract_offline_returns_policy():
    p = extract("smt_completeness/data/ir_openclaw.yaml", use_llm=False)
    assert isinstance(p, Policy)
    assert len(p.rules) == 24


def test_extract_non_yaml_without_llm_raises():
    with pytest.raises(ValueError, match="离线模式仅支持 YAML IR"):
        extract("README.md", use_llm=False)


def test_extract_with_llm_validates_policy_before_return(monkeypatch, tmp_path):
    doc = tmp_path / "source.md"
    doc.write_text("- 禁止读取凭据文件。\n", encoding="utf-8")
    invalid_policy = Policy(
        rules=[
            Rule(
                id="R1",
                source_anchor="缺失的原文锚点至少八个字",
                kind=RuleKind.MANDATORY_DENY,
                condition=Condition(flag_true=["destructive"]),
                decision=Decision.DENY,
                priority=Priority.MANDATORY,
                extraction_confidence="high",
            )
        ]
    )

    class _Completions:
        def create(self, **kwargs):
            return invalid_policy

    class _Client:
        chat = type("_Chat", (), {"completions": _Completions()})()

    monkeypatch.setattr(
        "smt_completeness.llm_client.build_instructor_client",
        lambda provider: _Client(),
    )
    monkeypatch.setattr(
        "smt_completeness.llm_client.resolve_model",
        lambda provider, model: "test-model",
    )

    with pytest.raises(ValueError, match="source_anchor"):
        _extract_with_llm(str(doc), provider="openai")


def test_vacuity_does_not_import_all_states_on_extractor():
    import smt_completeness.extractor as ext
    src = open(ext.__file__, encoding="utf-8").read()
    assert "all_states" not in src
