from smt_completeness.analysis.redundancy import check_duplicates, check_redundancy
from smt_completeness.extractor import load_offline_ir
from smt_completeness.ir import Condition, Policy, Priority, Rule, RuleKind
from smt_completeness.vocab import Decision, Operation, ResourceClass, TargetZone
from tests.policy_fixtures import make_rule


def _r(id, **cond):
    return Rule(
        id=id,
        source_anchor="s",
        kind=RuleKind.MAY_ALLOW,
        condition=Condition(**cond),
        decision=Decision.ALLOW,
        priority=Priority.LEARNED,
        extraction_confidence="high",
    )


def test_exact_duplicate_is_redundant():
    a = _r(
        "A",
        operation=[Operation.READ],
        resource_class=[ResourceClass.NORMAL_FILE],
        target_zone=[TargetZone.LOCAL],
    )
    b = _r(
        "B",
        operation=[Operation.READ],
        resource_class=[ResourceClass.NORMAL_FILE],
        target_zone=[TargetZone.LOCAL],
    )
    rep = check_redundancy(Policy(rules=[a, b]))
    # 两条完全重复，贪心固化后恰好删 1 条
    assert len(rep.redundant_rule_ids) == 1


def test_offline_policy_redundancy_runs():
    rep = check_redundancy(load_offline_ir())
    assert rep.total_rules == 24
    assert isinstance(rep.redundant_rule_ids, list)


def test_redundancy_module_has_no_all_states():
    from smt_completeness.analysis import redundancy as m

    assert "all_states" not in open(m.__file__, encoding="utf-8").read()


def test_contained_same_kind_rule_is_duplicate():
    wide = make_rule(
        "W",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
    )
    narrow = make_rule(
        "N",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
        target_zone=[TargetZone.LOCAL],
    )
    ids = check_duplicates(Policy(rules=[wide, narrow]))
    assert "N" in ids
    assert "W" not in ids


def test_different_kind_overlap_is_not_duplicate():
    deny = make_rule(
        "D",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
    )
    chal = make_rule(
        "C",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
    )
    assert check_duplicates(Policy(rules=[deny, chal])) == []
