from smt_completeness.completion import (
    verify_monotone,
    synthesize_rule_for_cube,
    run_completion,
)
from smt_completeness.analysis.coverage import check_coverage
from smt_completeness.extractor import load_offline_ir
from smt_completeness.ir import Policy, Rule, RuleKind, Priority, Condition
from smt_completeness.vocab import Operation, ResourceClass, TargetZone, Decision


def test_verify_monotone_true_when_only_tightening():
    base = load_offline_ir()
    extra = Rule(
        id="NEW",
        source_anchor="llm",
        kind=RuleKind.MANDATORY_DENY,
        condition=Condition(
            operation=[Operation.WRITE],
            resource_class=[ResourceClass.CREDENTIAL],
        ),
        decision=Decision.DENY,
        priority=Priority.MANDATORY,
        extraction_confidence="high",
    )
    tightened = Policy(rules=base.rules + [extra])
    assert verify_monotone(base, tightened) is True


def test_verify_monotone_false_when_loosening():
    base = load_offline_ir()
    loosen = Rule(
        id="BAD",
        source_anchor="x",
        kind=RuleKind.MAY_ALLOW,
        condition=Condition(
            operation=[Operation.EXECUTE],
            resource_class=[ResourceClass.UNKNOWN],
            target_zone=[TargetZone.EXTERNAL],
        ),
        decision=Decision.ALLOW,
        priority=Priority.LEARNED,
        extraction_confidence="low",
    )
    loosened = Policy(rules=base.rules + [loosen])
    assert verify_monotone(base, loosened) is False


def test_synthesize_rule_for_cube_creates_mandatory_deny_candidate():
    base = load_offline_ir()
    cube = check_coverage(base).danger_cubes[0]
    rule = synthesize_rule_for_cube(cube, idx=7)

    assert rule.id == "LLM-7"
    assert rule.kind is RuleKind.MANDATORY_DENY
    assert rule.decision is Decision.DENY
    assert rule.priority is Priority.MANDATORY


def test_run_completion_reduces_danger_and_converges():
    base = load_offline_ir()
    before = check_coverage(base).v_danger
    result = run_completion(base, max_rounds=5)
    after = check_coverage(result.final_policy).v_danger
    assert after <= before
    for rnd in result.rounds:
        assert rnd.monotone_ok is True
    assert isinstance(result.converged, bool)
