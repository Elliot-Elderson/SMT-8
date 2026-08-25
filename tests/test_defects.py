from smt_completeness.analysis.defects import check_defects, silent_permission_states
from smt_completeness.ir import Policy, RuleKind
from smt_completeness.vocab import Operation, ResourceClass, TargetZone
from tests.policy_fixtures import make_rule


def test_challenge_fully_covered_by_deny_is_dead():
    deny = make_rule(
        "D1",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
    )
    chal = make_rule(
        "C1",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
    )
    report = check_defects(Policy(rules=[deny, chal]))
    ids = [item.rule_id for item in report.dead_clauses]
    assert "C1" in ids
    assert "D1" not in ids
    dead = next(item for item in report.dead_clauses if item.rule_id == "C1")
    assert dead.hit_volume > 0
    assert "D1" in dead.covering_rule_ids


def test_challenge_only_partially_covered_is_not_dead():
    deny = make_rule(
        "D1",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
        flag_true=["destructive"],
    )
    chal = make_rule(
        "C1",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
    )
    report = check_defects(Policy(rules=[deny, chal]))
    assert "C1" not in [item.rule_id for item in report.dead_clauses]
    chal_ratio = next(item for item in report.overlap_ratios if item.rule_id == "C1")
    assert 0 < chal_ratio.effective_volume < chal_ratio.hit_volume


def test_allow_fully_covered_is_dead():
    deny = make_rule(
        "D1",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
    )
    allow = make_rule(
        "A1",
        RuleKind.MAY_ALLOW,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
    )
    report = check_defects(Policy(rules=[deny, allow]))
    assert "A1" in [item.rule_id for item in report.dead_clauses]


def test_empty_policy_has_twenty_silent_permissions():
    states = silent_permission_states(Policy(rules=[]))
    assert len(states) == 20
    report = check_defects(Policy(rules=[]))
    assert report.silent_permission_volume == 20
    assert report.precedence_overlap_volume == 0


def test_matched_default_allow_is_not_silent():
    allow = make_rule(
        "A1",
        RuleKind.MAY_ALLOW,
        operation=[Operation.READ],
        resource_class=[ResourceClass.NORMAL_FILE],
        target_zone=[TargetZone.LOCAL],
    )
    states = silent_permission_states(Policy(rules=[allow]))
    assert not any(
        s.operation is Operation.READ and s.resource_class is ResourceClass.NORMAL_FILE
        for s in states
    )


def test_defects_module_has_no_all_states():
    from smt_completeness.analysis import defects as m

    assert "all_states" not in open(m.__file__, encoding="utf-8").read()
