import pytest
from pydantic import ValidationError

from smt_completeness.ir import Condition, Provenance, Rule, RuleKind, Priority, Policy
from smt_completeness.state_space import State
from smt_completeness.vocab import Operation, ResourceClass, TargetZone, Decision


def _rule(**kw):
    base = dict(
        id="R1", source_anchor="§3.1", kind=RuleKind.MANDATORY_DENY,
        condition=Condition(operation=[Operation.READ],
                            resource_class=[ResourceClass.CREDENTIAL]),
        decision=Decision.DENY, priority=Priority.MANDATORY,
        extraction_confidence="high",
    )
    base.update(kw)
    return Rule(**base)


def test_wildcard_condition_matches_any():
    c = Condition()
    s = State(Operation.WRITE, ResourceClass.NORMAL_FILE, TargetZone.LOCAL, frozenset())
    assert c.matches(s) is True


def test_condition_matches_flags():
    c = Condition(operation=[Operation.SEND], flag_true=["taint_credential"],
                  flag_false=["destructive"])
    hit = State(Operation.SEND, ResourceClass.NORMAL_FILE, TargetZone.EXTERNAL,
                frozenset({"taint_credential"}))
    miss_flag = State(Operation.SEND, ResourceClass.NORMAL_FILE, TargetZone.EXTERNAL,
                      frozenset({"taint_credential", "destructive"}))
    miss_op = State(Operation.READ, ResourceClass.NORMAL_FILE, TargetZone.EXTERNAL,
                    frozenset({"taint_credential"}))
    assert c.matches(hit) is True
    assert c.matches(miss_flag) is False
    assert c.matches(miss_op) is False


def test_unknown_flag_name_rejected():
    with pytest.raises(ValidationError):
        Condition(flag_true=["not_a_real_flag"])


def test_rules_of_kind():
    p = Policy(rules=[_rule(id="R1"), _rule(id="R2", kind=RuleKind.MAY_ALLOW,
                                            decision=Decision.ALLOW)])
    assert [r.id for r in p.rules_of_kind(RuleKind.MANDATORY_DENY)] == ["R1"]


def test_rule_kind_must_match_decision():
    with pytest.raises(ValidationError):
        _rule(kind=RuleKind.MANDATORY_DENY, decision=Decision.ALLOW)
    with pytest.raises(ValidationError):
        _rule(kind=RuleKind.MUST_CHALLENGE, decision=Decision.DENY)
    with pytest.raises(ValidationError):
        _rule(kind=RuleKind.MAY_ALLOW, decision=Decision.CHALLENGE)

    assert _rule(kind=RuleKind.MANDATORY_DENY, decision=Decision.DENY).id == "R1"
    assert _rule(kind=RuleKind.MUST_CHALLENGE, decision=Decision.CHALLENGE,
                 id="R-chal").id == "R-chal"
    assert _rule(kind=RuleKind.MAY_ALLOW, decision=Decision.ALLOW,
                 id="R-allow").id == "R-allow"


def test_decision_rule_requires_at_least_one_literal():
    with pytest.raises(ValidationError, match="至少一个条件"):
        Rule(
            id="X",
            source_anchor="禁止读取凭据文件和凭据目录",
            kind=RuleKind.MUST_CHALLENGE,
            condition=Condition(),
            decision=Decision.CHALLENGE,
            priority=Priority.MANDATORY,
            extraction_confidence="high",
        )


def test_single_flag_deny_still_valid():
    r = Rule(
        id="R3.2.1",
        source_anchor="禁止系统破坏",
        kind=RuleKind.MANDATORY_DENY,
        condition=Condition(flag_true=["destructive"]),
        decision=Decision.DENY,
        priority=Priority.MANDATORY,
        extraction_confidence="high",
    )
    assert r.condition.flag_true == ["destructive"]


def test_synthesized_provenance_accepted():
    r = Rule(
        id="SYN-0-1",
        source_anchor="补全 · 倒挂对齐",
        kind=RuleKind.MANDATORY_DENY,
        condition=Condition(flag_true=["destructive"]),
        decision=Decision.DENY,
        priority=Priority.MANDATORY,
        extraction_confidence="medium",
        provenance=Provenance.SYNTHESIZED,
    )
    assert r.provenance is Provenance.SYNTHESIZED
    assert r.provenance.value == "synthesized"


def test_decision_kinds_is_public():
    from smt_completeness.ir import DECISION_KINDS, RuleKind

    assert DECISION_KINDS == {
        RuleKind.MANDATORY_DENY,
        RuleKind.MUST_CHALLENGE,
        RuleKind.MAY_ALLOW,
    }


def test_justification_round_trip_on_synthesized_rule():
    from smt_completeness.ir import Justification

    just = Justification(
        defect="sensitivity_gap",
        evidence_rule_ids=["R3.6"],
        witness={
            "operation": "send",
            "resource_class": "system_sensitive",
            "target_zone": "external",
            "flags": [],
        },
        witness_decision_before=1,
        witness_decision_after=2,
    )
    r = _rule(
        id="SYN-0-1",
        provenance=Provenance.SYNTHESIZED,
        justification=just,
    )
    assert r.justification is not None
    assert r.justification.defect == "sensitivity_gap"
    assert r.justification.evidence_rule_ids == ["R3.6"]
    dumped = r.model_dump(mode="json")
    assert dumped["justification"]["witness"]["operation"] == "send"


def test_extracted_rule_justification_defaults_none():
    assert _rule().justification is None
