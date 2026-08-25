from smt_completeness.analysis.evidence import enumerate_justified_gaps
from smt_completeness.ir import Policy, Provenance, RuleKind
from smt_completeness.vocab import Operation, ResourceClass, TargetZone
from tests.policy_fixtures import make_rule


def test_extracted_deny_justifies_higher_sensitivity_gap():
    evidence = make_rule(
        "R3.6",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.SEND],
        resource_class=[ResourceClass.PRIVATE_DATA],
        target_zone=[TargetZone.EXTERNAL, TargetZone.UNKNOWN],
    )
    report = enumerate_justified_gaps(Policy(rules=[evidence]))
    matches = [
        gap
        for gap in report.gaps
        if gap.resource_class is ResourceClass.SYSTEM_SENSITIVE
        and gap.operation is Operation.SEND
    ]
    assert len(matches) == 1
    gap = matches[0]
    assert gap.kind is RuleKind.MANDATORY_DENY
    assert gap.target_zone == [TargetZone.EXTERNAL, TargetZone.UNKNOWN]
    cond = gap.to_condition()
    assert cond.target_zone == [TargetZone.EXTERNAL, TargetZone.UNKNOWN]
    assert cond.operation == [Operation.SEND]
    assert cond.resource_class == [ResourceClass.SYSTEM_SENSITIVE]


def test_default_decision_is_not_justified_evidence():
    report = enumerate_justified_gaps(Policy(rules=[]))
    assert report.justified_gap_count == 0
    assert report.gaps == []


def test_synthesized_rule_cannot_justify_a_gap():
    syn = make_rule(
        "SYN-0-1",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.SEND],
        resource_class=[ResourceClass.PRIVATE_DATA],
        target_zone=[TargetZone.EXTERNAL, TargetZone.UNKNOWN],
        provenance=Provenance.SYNTHESIZED,
    )
    report = enumerate_justified_gaps(Policy(rules=[syn]))
    assert report.justified_gap_count == 0


def test_equal_rank_lifts_the_weaker_side():
    evidence = make_rule(
        "R3.4",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.AGENT_PRIVATE_CONTEXT],
    )
    report = enumerate_justified_gaps(Policy(rules=[evidence]))
    memory = [
        gap
        for gap in report.gaps
        if gap.resource_class is ResourceClass.AGENT_MEMORY
        and gap.operation is Operation.READ
    ]
    assert len(memory) == 1
    assert memory[0].kind is RuleKind.MANDATORY_DENY
    assert memory[0].target_zone == []


def test_evidence_module_has_no_all_states():
    from smt_completeness.analysis import evidence as m

    assert "all_states" not in open(m.__file__, encoding="utf-8").read()
