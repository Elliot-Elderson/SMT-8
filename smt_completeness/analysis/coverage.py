from pydantic import BaseModel

from ..compiler import is_default_allow
from ..ir import Policy, RuleKind
from ..state_space import State, all_states
from ..vocab import ALL_FLAGS, Operation, ResourceClass, TargetZone


class Cube(BaseModel):
    operation: list[str]
    resource_class: list[str]
    target_zone: list[str]
    flag_true: list[str]
    flag_false: list[str]
    size: int


class CoverageReport(BaseModel):
    total: int
    v_explicit: int
    v_danger: int
    v_deferred: int
    v_explicit_ratio: float
    v_danger_ratio: float
    v_deferred_ratio: float
    danger_cubes: list[Cube]


def _any_rule_matches(policy: Policy, state: State) -> bool:
    for kind in (RuleKind.MANDATORY_DENY, RuleKind.MUST_CHALLENGE, RuleKind.MAY_ALLOW):
        if any(rule.condition.matches(state) for rule in policy.rules_of_kind(kind)):
            return True
    return False


def generalize_cubes(states: list[State]) -> list[Cube]:
    """Greedily generalize danger points by dropping literals when safe."""
    point_set = set(states)
    remaining = set(states)
    cubes: list[Cube] = []

    def cube_states(op, rc, tz, ftrue, ffalse):
        ops = [op] if op is not None else list(Operation)
        rcs = [rc] if rc is not None else list(ResourceClass)
        tzs = [tz] if tz is not None else list(TargetZone)
        free = [flag for flag in ALL_FLAGS if flag not in ftrue and flag not in ffalse]
        result = []
        for operation in ops:
            for resource_class in rcs:
                for target_zone in tzs:
                    for mask in range(2 ** len(free)):
                        flags = set(ftrue)
                        for bit, flag in enumerate(free):
                            if mask & (1 << bit):
                                flags.add(flag)
                        result.append(
                            State(
                                operation,
                                resource_class,
                                target_zone,
                                frozenset(flags),
                            )
                        )
        return result

    while remaining:
        seed = next(iter(remaining))
        op = seed.operation
        rc = seed.resource_class
        tz = seed.target_zone
        ftrue = set(seed.flags)
        ffalse = set(ALL_FLAGS) - set(seed.flags)

        for dim in ("operation", "resource_class", "target_zone"):
            trial_op = None if dim == "operation" else op
            trial_rc = None if dim == "resource_class" else rc
            trial_tz = None if dim == "target_zone" else tz
            block = cube_states(trial_op, trial_rc, trial_tz, ftrue, ffalse)
            if all(state in point_set for state in block):
                if dim == "operation":
                    op = None
                elif dim == "resource_class":
                    rc = None
                else:
                    tz = None

        for flag in list(ALL_FLAGS):
            trial_ftrue = ftrue - {flag}
            trial_ffalse = ffalse - {flag}
            block = cube_states(op, rc, tz, trial_ftrue, trial_ffalse)
            if all(state in point_set for state in block):
                ftrue.discard(flag)
                ffalse.discard(flag)

        covered = cube_states(op, rc, tz, ftrue, ffalse)
        remaining -= set(covered)
        cubes.append(
            Cube(
                operation=[op.value] if op else [],
                resource_class=[rc.value] if rc else [],
                target_zone=[tz.value] if tz else [],
                flag_true=sorted(ftrue),
                flag_false=sorted(ffalse),
                size=len(covered),
            )
        )

    return cubes


def check_coverage(policy: Policy) -> CoverageReport:
    explicit = 0
    danger_states: list[State] = []
    deferred = 0

    for state in all_states():
        if _any_rule_matches(policy, state):
            explicit += 1
        elif is_default_allow(state):
            danger_states.append(state)
        else:
            deferred += 1

    total = explicit + len(danger_states) + deferred
    return CoverageReport(
        total=total,
        v_explicit=explicit,
        v_danger=len(danger_states),
        v_deferred=deferred,
        v_explicit_ratio=explicit / total,
        v_danger_ratio=len(danger_states) / total,
        v_deferred_ratio=deferred / total,
        danger_cubes=generalize_cubes(danger_states),
    )
