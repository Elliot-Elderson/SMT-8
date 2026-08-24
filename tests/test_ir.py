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
