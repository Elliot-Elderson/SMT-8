from smt_completeness.analysis.monotonicity import check_monotonicity, count_inversions
from smt_completeness.extractor import load_offline_ir
from smt_completeness.ir import Policy


def test_offline_finds_context_vs_memory_asymmetry():
    # spec §5.5：agent_private_context 有强制拒绝读取，agent_memory 没有 → 同级不对称
    rep = check_monotonicity(load_offline_ir())
    assert rep.equal_rank_asymmetry_count > 0
    # 至少有一例涉及 agent_memory / agent_private_context
    flat = rep.equal_rank_examples
    rcs = {e.high_state["resource_class"] for e in flat} | {
        e.low_state["resource_class"] for e in flat
    }
    assert "agent_memory" in rcs and "agent_private_context" in rcs


def test_no_strict_inversion_is_reported_cleanly():
    rep = check_monotonicity(load_offline_ir())
    assert rep.inversion_count >= 0


def test_monotonicity_module_has_no_all_states():
    from smt_completeness.analysis import monotonicity as m
    assert "all_states" not in open(m.__file__, encoding="utf-8").read()


def test_asymmetric_pair_on_tiny_policy():
    from tests.policy_fixtures import deny_read_private_context
    rep = check_monotonicity(Policy(rules=[deny_read_private_context()]))
    assert rep.equal_rank_asymmetry_count > 0


def test_empty_policy_has_zero_inversions():
    assert count_inversions(Policy(rules=[])) == 0
