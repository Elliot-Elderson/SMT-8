import z3
from pydantic import BaseModel

from ..bdd_env import PairBDDEnv
from ..compiler import Z3Env
from ..ir import Policy
from ..state_space import State
from ..vocab import ALL_FLAGS, Operation, ResourceClass, TargetZone, sensitivity_rank
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


def count_inversions(policy: Policy) -> int:
    return PairBDDEnv(policy).count_inversions()


def _find_pair_examples(
    policy: Policy,
    constraint_fn,
    *,
    max_examples: int = 20,
) -> list[tuple[State, State, int, int]]:
    """Collect up to max_examples (s1, s2, D1, D2) pairs via Z3 push/pop blocking."""
    env = Z3Env(policy)
    rc2 = z3.Const("smtc_rc2_mono", env.rc_sort)

    D1 = env.decision_expr(policy)
    D2 = z3.substitute(D1, (env.rc, rc2))

    solver = z3.Solver()
    solver.add(constraint_fn(env, rc2, D1, D2))

    results: list[tuple[State, State, int, int]] = []
    while len(results) < max_examples:
        if solver.check() != z3.sat:
            break
        model = solver.model()
        op_val = str(model.eval(env.op, model_completion=True))
        rc1_val = str(model.eval(env.rc, model_completion=True))
        rc2_val = str(model.eval(rc2, model_completion=True))
        tz_val = str(model.eval(env.tz, model_completion=True))
        flags = frozenset(
            name for name, fv in env.flag.items()
            if z3.is_true(model.eval(fv, model_completion=True))
        )
        d1_val = int(str(model.eval(D1, model_completion=True)))
        d2_val = int(str(model.eval(D2, model_completion=True)))

        s1 = State(Operation(op_val), ResourceClass(rc1_val), TargetZone(tz_val), flags)
        s2 = State(Operation(op_val), ResourceClass(rc2_val), TargetZone(tz_val), flags)
        results.append((s1, s2, d1_val, d2_val))

        blocking_lits = [
            env.op == env._op_map[op_val],
            env.rc == env._rc_map[rc1_val],
            rc2 == env._rc_map[rc2_val],
            env.tz == env._tz_map[tz_val],
        ]
        for fname, fv in env.flag.items():
            blocking_lits.append(fv if fname in flags else z3.Not(fv))
        solver.add(z3.Not(z3.And(blocking_lits)))

    return results


def _build_inversion_constraint(ranked, ranks):
    def constraint(env, rc2, D1, D2):
        options = [
            z3.And(env.rc == env._rc_map[h.value], rc2 == env._rc_map[l.value])
            for h in ranked for l in ranked if ranks[h] > ranks[l]
        ]
        if not options:
            return z3.BoolVal(False)
        return z3.And(z3.Or(options), D1 < D2)

    return constraint


def find_inversion_pair(policy: Policy) -> tuple[State, State] | None:
    """Find one state pair where rank(rc1) > rank(rc2) and D(rc1) < D(rc2)."""
    ranked = [rc for rc in ResourceClass if sensitivity_rank(rc) is not None]
    ranks = {rc: sensitivity_rank(rc) for rc in ranked}
    pairs = _find_pair_examples(
        policy, _build_inversion_constraint(ranked, ranks), max_examples=1
    )
    if not pairs:
        return None
    s1, s2, _, _ = pairs[0]
    return (s1, s2)


def check_monotonicity(policy: Policy) -> MonotonicityReport:
    """Check sensitivity monotonicity and equal-rank asymmetry from spec §5.5.

    Only state pairs that differ by resource_class are compared. Higher numeric
    decisions are stricter: allow=0, challenge=1, deny=2.
    Counts via PairBDDEnv; examples via Z3 with push/pop blocking (≤20 each).
    """
    ranked = [rc for rc in ResourceClass if sensitivity_rank(rc) is not None]
    ranks = {rc: sensitivity_rank(rc) for rc in ranked}

    pair_env = PairBDDEnv(policy)
    inversion_count = pair_env.count_inversions()
    asymmetry_count = pair_env.count_equal_rank_asymmetry()

    inversion_pairs = _find_pair_examples(
        policy, _build_inversion_constraint(ranked, ranks)
    )
    inversions = [
        InversionExample(
            high_state=state_to_dict(s1),
            low_state=state_to_dict(s2),
            high_decision=d1,
            low_decision=d2,
        )
        for s1, s2, d1, d2 in inversion_pairs
    ]

    equal_rank_rc_pairs = [
        (h, l) for h in ranked for l in ranked
        if ranks[h] == ranks[l] and h.value < l.value
    ]
    asymmetry_examples: list[InversionExample] = []
    if equal_rank_rc_pairs:
        def equal_rank_constraint(env, rc2, D1, D2):
            options = [
                z3.And(env.rc == env._rc_map[h.value], rc2 == env._rc_map[l.value])
                for h, l in equal_rank_rc_pairs
            ]
            return z3.And(z3.Or(options), D1 != D2)

        asymmetry_pairs = _find_pair_examples(policy, equal_rank_constraint)
        asymmetry_examples = [
            InversionExample(
                high_state=state_to_dict(s1),
                low_state=state_to_dict(s2),
                high_decision=d1,
                low_decision=d2,
            )
            for s1, s2, d1, d2 in asymmetry_pairs
        ]

    return MonotonicityReport(
        inversion_count=inversion_count,
        inversion_examples=inversions,
        equal_rank_asymmetry_count=asymmetry_count,
        equal_rank_examples=asymmetry_examples,
    )
