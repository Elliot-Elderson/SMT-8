from pydantic import BaseModel

from ..compiler import decide_py
from ..ir import Policy
from ..state_space import State, all_states
from ..vocab import ResourceClass, sensitivity_rank
from .consistency import state_to_dict


class InversionExample(BaseModel):
    high_state: dict
    low_state: dict
    high_decision: int
    low_decision: int


class MonotonicityReport(BaseModel):
    inversion_count: int
    inversion_examples: list[InversionExample]
    equal_rank_asymmetry_count: int
    equal_rank_examples: list[InversionExample]


def _with_rc(state: State, resource_class: ResourceClass) -> State:
    return State(state.operation, resource_class, state.target_zone, state.flags)


def check_monotonicity(policy: Policy) -> MonotonicityReport:
    """Check sensitivity monotonicity and equal-rank asymmetry from spec §5.5.

    Only state pairs that differ by resource_class are compared. Higher numeric
    decisions are stricter: allow=0, challenge=1, deny=2.
    """
    ranked = [rc for rc in ResourceClass if sensitivity_rank(rc) is not None]
    ranks = {rc: sensitivity_rank(rc) for rc in ranked}
    inversions: list[InversionExample] = []
    asymmetries: list[InversionExample] = []
    inversion_count = 0
    asymmetry_count = 0
    seen_contexts = set()

    for state in all_states():
        context_key = (state.operation, state.target_zone, state.flags)
        if context_key in seen_contexts:
            continue
        seen_contexts.add(context_key)

        states_by_rc = {rc: _with_rc(state, rc) for rc in ranked}
        decisions = {rc: int(decide_py(states_by_rc[rc], policy)) for rc in ranked}

        for high_rc in ranked:
            for low_rc in ranked:
                if high_rc == low_rc:
                    continue

                high_rank = ranks[high_rc]
                low_rank = ranks[low_rc]
                high_decision = decisions[high_rc]
                low_decision = decisions[low_rc]

                if high_rank > low_rank and high_decision < low_decision:
                    inversion_count += 1
                    if len(inversions) < 20:
                        inversions.append(
                            InversionExample(
                                high_state=state_to_dict(states_by_rc[high_rc]),
                                low_state=state_to_dict(states_by_rc[low_rc]),
                                high_decision=high_decision,
                                low_decision=low_decision,
                            )
                        )

                if (
                    high_rank == low_rank
                    and high_rc.value < low_rc.value
                    and high_decision != low_decision
                ):
                    asymmetry_count += 1
                    if len(asymmetries) < 20:
                        asymmetries.append(
                            InversionExample(
                                high_state=state_to_dict(states_by_rc[high_rc]),
                                low_state=state_to_dict(states_by_rc[low_rc]),
                                high_decision=high_decision,
                                low_decision=low_decision,
                            )
                        )

    return MonotonicityReport(
        inversion_count=inversion_count,
        inversion_examples=inversions,
        equal_rank_asymmetry_count=asymmetry_count,
        equal_rank_examples=asymmetries,
    )
