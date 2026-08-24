from smt_completeness.analysis.monotonicity import check_monotonicity
from smt_completeness.compiler import is_monotone, preserves_mustallow
from smt_completeness.completion import run_completion
from smt_completeness.ir import Policy, Provenance, RuleKind
from smt_completeness.vocab import ResourceClass
from tests.policy_fixtures import deny_read_private_context


def test_completion_aligns_memory_not_deny_default_allow():
    base = Policy(rules=[deny_read_private_context()])
    before_inv = check_monotonicity(base).equal_rank_asymmetry_count
    result = run_completion(base, max_rounds=5)
    assert is_monotone(base, result.final_policy)
    assert preserves_mustallow(base, result.final_policy)
    after_inv = check_monotonicity(result.final_policy).equal_rank_asymmetry_count
    assert after_inv <= before_inv
    syn = [r for r in result.final_policy.rules if r.provenance is Provenance.SYNTHESIZED]
    assert any(
        ResourceClass.AGENT_MEMORY in r.condition.resource_class for r in syn
    )
    deny_unspecified_allow = any(
        r.kind is RuleKind.MANDATORY_DENY
        and not r.condition.flag_true
        and r.condition.operation
        and set(o.value for o in r.condition.operation) <= {"read", "list"}
        and r.condition.resource_class == []
        for r in syn
    )
    assert deny_unspecified_allow is False


def test_completion_module_has_no_all_states():
    from smt_completeness import completion as m
    assert "all_states" not in open(m.__file__, encoding="utf-8").read()
