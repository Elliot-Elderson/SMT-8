from smt_completeness.extractor import load_offline_ir, self_check, extract
from smt_completeness.ir import Rule, RuleKind, Priority, Condition, Policy
from smt_completeness.vocab import Decision


def test_offline_ir_loads_and_passes_self_check():
    p = load_offline_ir()
    assert len(p.rules) == 24
    rep = self_check(p)
    assert rep.ok is True
    assert rep.id_unique is True
    assert rep.vacuous_rule_ids == []


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
