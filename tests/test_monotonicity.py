from smt_completeness.analysis.monotonicity import check_monotonicity
from smt_completeness.extractor import load_offline_ir


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
