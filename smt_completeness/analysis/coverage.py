import z3
from pydantic import BaseModel

from ..bdd_env import BDDEnv
from ..compiler import find_witness
from ..cubes import Cube, generalize
from ..ir import Policy, RuleKind
from ..state_space import State


class CoverageReport(BaseModel):
    total: int
    v_explicit: int
    v_unspecified: int
    v_unspecified_allow: int
    v_unspecified_challenge: int
    v_explicit_ratio: float
    v_unspecified_ratio: float
    v_unspecified_allow_ratio: float
    v_unspecified_challenge_ratio: float
    unspecified_cubes: list[Cube]
    fallback_cubes: list[Cube]


def _unspecified_constraint(blocked: list[State], *, exclude_default_allow: bool = False):
    def constraint(e):
        any_rule = z3.Or(
            e._kind_or(RuleKind.MANDATORY_DENY),
            e._kind_or(RuleKind.MUST_CHALLENGE),
            e._kind_or(RuleKind.MAY_ALLOW),
        )
        parts = [z3.Not(any_rule), *[z3.Not(e.state_eq(state)) for state in blocked]]
        if exclude_default_allow:
            parts.append(z3.Not(e.default_allow_expr()))
        return z3.And(*parts)

    return constraint


def _unspecified_cubes(
    policy: Policy,
    env: BDDEnv,
    target,
    *,
    exclude_default_allow: bool = False,
) -> list[Cube]:
    seeds: list[State] = []
    cubes: list[Cube] = []

    for _ in range(16):
        seed = find_witness(
            policy,
            _unspecified_constraint(seeds, exclude_default_allow=exclude_default_allow),
        )
        if seed is None:
            break
        seeds.append(seed)
        cube = generalize(env, seed, target)
        if cube is not None:
            cubes.append(cube)

    return _merge_containing_cubes(cubes)


def _merge_containing_cubes(cubes: list[Cube]) -> list[Cube]:
    kept: list[Cube] = []
    for cube in sorted(cubes, key=lambda item: item.size, reverse=True):
        if any(_contains(existing, cube) for existing in kept):
            continue
        kept = [existing for existing in kept if not _contains(cube, existing)]
        kept.append(cube)
    return kept


def _contains(outer: Cube, inner: Cube) -> bool:
    return (
        _dimension_contains(outer.operation, inner.operation)
        and _dimension_contains(outer.resource_class, inner.resource_class)
        and _dimension_contains(outer.target_zone, inner.target_zone)
        and set(outer.flag_true).issubset(inner.flag_true)
        and set(outer.flag_false).issubset(inner.flag_false)
    )


def _dimension_contains(outer: list[str], inner: list[str]) -> bool:
    if not outer:
        return True
    if not inner:
        return False
    return set(inner).issubset(outer)


def check_coverage(policy: Policy) -> CoverageReport:
    env = BDDEnv(policy)
    valid = env.valid
    any_match = env.any_match()
    unspecified = valid & ~any_match
    explicit = env.count(valid & any_match)
    unspecified_count = env.count(unspecified)
    unspecified_allow = env.count(unspecified & env.default_allow())
    unspecified_challenge = unspecified_count - unspecified_allow
    total = env.count(valid)
    fallback = unspecified & ~env.default_allow()

    return CoverageReport(
        total=total,
        v_explicit=explicit,
        v_unspecified=unspecified_count,
        v_unspecified_allow=unspecified_allow,
        v_unspecified_challenge=unspecified_challenge,
        v_explicit_ratio=explicit / total,
        v_unspecified_ratio=unspecified_count / total,
        v_unspecified_allow_ratio=unspecified_allow / total,
        v_unspecified_challenge_ratio=unspecified_challenge / total,
        unspecified_cubes=_unspecified_cubes(policy, env, unspecified),
        fallback_cubes=_unspecified_cubes(
            policy, env, fallback, exclude_default_allow=True
        ),
    )
