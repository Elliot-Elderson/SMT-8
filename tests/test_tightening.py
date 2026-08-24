from smt_completeness.analysis.tightening import check_tightening
from smt_completeness.extractor import load_offline_ir
from smt_completeness.ir import Condition, Policy, Priority, Rule, RuleKind
from smt_completeness.vocab import Decision, Operation, ResourceClass, TargetZone


def test_allow_rule_with_no_mustallow_dependency_is_tightenable():
    # 单独一条 allow：MustAllow=该 allow 区；上调后这些状态变 challenge → 破坏 MustAllow。
    allow = Rule(
        id="A",
        source_anchor="s",
        kind=RuleKind.MAY_ALLOW,
        condition=Condition(
            operation=[Operation.READ],
            resource_class=[ResourceClass.NORMAL_FILE],
            target_zone=[TargetZone.LOCAL],
        ),
        decision=Decision.ALLOW,
        priority=Priority.LEARNED,
        extraction_confidence="high",
    )
    rep = check_tightening(Policy(rules=[allow]))
    assert "A" not in rep.tightenable_rule_ids
    assert "A" in rep.witnessed_rule_ids


def test_offline_policy_tightening_runs():
    rep = check_tightening(load_offline_ir())
    assert isinstance(rep.is_h1_tight, bool)
    assert isinstance(rep.tightenable_rule_ids, list)


def test_tightening_module_has_no_all_states():
    from smt_completeness.analysis import tightening as m

    assert "all_states" not in open(m.__file__, encoding="utf-8").read()
