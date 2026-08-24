from smt_completeness.analysis.consistency import check_consistency, state_to_dict
from smt_completeness.extractor import load_offline_ir
from smt_completeness.ir import Policy, Rule, RuleKind, Priority, Condition
from smt_completeness.vocab import Operation, ResourceClass, TargetZone, Decision
from smt_completeness.state_space import State


def test_no_overlap_when_disjoint():
    deny = Rule(id="D", source_anchor="s", kind=RuleKind.MANDATORY_DENY,
                condition=Condition(operation=[Operation.READ],
                                    resource_class=[ResourceClass.CREDENTIAL]),
                decision=Decision.DENY, priority=Priority.MANDATORY,
                extraction_confidence="high")
    chal = Rule(id="C", source_anchor="s", kind=RuleKind.MUST_CHALLENGE,
                condition=Condition(operation=[Operation.SEND],
                                    resource_class=[ResourceClass.NORMAL_FILE]),
                decision=Decision.CHALLENGE, priority=Priority.MANDATORY,
                extraction_confidence="high")
    rep = check_consistency(Policy(rules=[deny, chal]))
    assert rep.overlap_count == 0
    assert rep.example_state is None
    assert rep.deny_rule_ids == []
    assert rep.challenge_rule_ids == []


def test_overlap_detected_and_reconciled():
    # destructive 的 send normal_file external 同时命中 deny(destructive) 与 challenge(§4.1)
    deny = Rule(id="D", source_anchor="s", kind=RuleKind.MANDATORY_DENY,
                condition=Condition(flag_true=["destructive"]),
                decision=Decision.DENY, priority=Priority.MANDATORY,
                extraction_confidence="high")
    chal = Rule(id="C", source_anchor="s", kind=RuleKind.MUST_CHALLENGE,
                condition=Condition(operation=[Operation.SEND],
                                    resource_class=[ResourceClass.NORMAL_FILE],
                                    target_zone=[TargetZone.EXTERNAL]),
                decision=Decision.CHALLENGE, priority=Priority.MANDATORY,
                extraction_confidence="high")
    rep = check_consistency(Policy(rules=[deny, chal]))
    assert rep.overlap_count > 0
    assert rep.example_state is not None
    assert rep.deny_rule_ids == ["D"]
    assert rep.challenge_rule_ids == ["C"]


def test_overlap_rule_ids_only_matching_subset():
    deny_overlap = Rule(
        id="D-overlap", source_anchor="s", kind=RuleKind.MANDATORY_DENY,
        condition=Condition(flag_true=["destructive"]),
        decision=Decision.DENY, priority=Priority.MANDATORY,
        extraction_confidence="high",
    )
    deny_unrelated = Rule(
        id="D-unrelated", source_anchor="s", kind=RuleKind.MANDATORY_DENY,
        condition=Condition(operation=[Operation.READ],
                            resource_class=[ResourceClass.CREDENTIAL]),
        decision=Decision.DENY, priority=Priority.MANDATORY,
        extraction_confidence="high",
    )
    chal = Rule(
        id="C", source_anchor="s", kind=RuleKind.MUST_CHALLENGE,
        condition=Condition(operation=[Operation.SEND],
                            resource_class=[ResourceClass.NORMAL_FILE],
                            target_zone=[TargetZone.EXTERNAL]),
        decision=Decision.CHALLENGE, priority=Priority.MANDATORY,
        extraction_confidence="high",
    )
    rep = check_consistency(Policy(rules=[deny_overlap, deny_unrelated, chal]))
    assert rep.overlap_count > 0
    assert rep.deny_rule_ids == ["D-overlap"]
    assert "D-unrelated" not in rep.deny_rule_ids
    assert rep.challenge_rule_ids == ["C"]


def test_state_to_dict_roundtrip_keys():
    s = State(Operation.READ, ResourceClass.CREDENTIAL, TargetZone.LOCAL,
              frozenset({"destructive"}))
    d = state_to_dict(s)
    assert d["operation"] == "read"
    assert d["resource_class"] == "credential"
    assert d["flags"] == ["destructive"]


def test_consistency_module_has_no_all_states():
    from smt_completeness.analysis import consistency as m

    assert "all_states" not in open(m.__file__, encoding="utf-8").read()
