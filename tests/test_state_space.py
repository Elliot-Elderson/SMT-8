from smt_completeness.state_space import (
    State, all_states, state_count, EXPECTED_STATE_COUNT,
)
from smt_completeness.vocab import Operation, ResourceClass, TargetZone


def test_state_count_matches_product():
    # 6 * 10 * 4 * 2**9
    assert EXPECTED_STATE_COUNT == 6 * 10 * 4 * (2 ** 9)
    assert state_count() == EXPECTED_STATE_COUNT


def test_states_are_unique_and_hashable():
    seen = set(all_states())
    assert len(seen) == EXPECTED_STATE_COUNT


def test_state_is_frozen():
    s = State(Operation.READ, ResourceClass.NORMAL_FILE, TargetZone.LOCAL, frozenset())
    assert s in set(all_states())
