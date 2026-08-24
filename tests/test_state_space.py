from smt_completeness.state_space import EXPECTED_STATE_COUNT
from smt_completeness.vocab import ALL_FLAGS, Operation, ResourceClass, TargetZone


def test_expected_state_count_formula():
    assert EXPECTED_STATE_COUNT == len(Operation) * len(ResourceClass) * len(TargetZone) * (2 ** len(ALL_FLAGS))
    assert EXPECTED_STATE_COUNT == 122880
