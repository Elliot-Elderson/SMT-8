from itertools import combinations

from pydantic import BaseModel

from .bdd_env import BDDEnv
from .state_space import State
from .vocab import ALL_FLAGS, Operation, ResourceClass, TargetZone


MAX_LITERALS = 3


class Cube(BaseModel):
    operation: list[str]
    resource_class: list[str]
    target_zone: list[str]
    flag_true: list[str]
    flag_false: list[str]
    size: int


def literal_count(cube: Cube) -> int:
    enum_literals = sum(
        1
        for values in (cube.operation, cube.resource_class, cube.target_zone)
        if values
    )
    return enum_literals + len(cube.flag_true) + len(cube.flag_false)


def cube_size(cube: Cube) -> int:
    operation_count = len(cube.operation) if cube.operation else len(Operation)
    resource_class_count = (
        len(cube.resource_class) if cube.resource_class else len(ResourceClass)
    )
    target_zone_count = len(cube.target_zone) if cube.target_zone else len(TargetZone)
    free_flags = len(ALL_FLAGS) - len(cube.flag_true) - len(cube.flag_false)
    return operation_count * resource_class_count * target_zone_count * (2**free_flags)


def state_to_full_cube(state: State) -> Cube:
    return _with_size(
        Cube(
            operation=[state.operation.value],
            resource_class=[state.resource_class.value],
            target_zone=[state.target_zone.value],
            flag_true=sorted(state.flags),
            flag_false=sorted(set(ALL_FLAGS) - set(state.flags)),
            size=0,
        )
    )


def cube_to_bdd(env: BDDEnv, cube: Cube):
    parts = []
    if cube.operation:
        parts.append(env._or([env.bdd.var(f"op_{value}") for value in cube.operation]))
    if cube.resource_class:
        parts.append(
            env._or([env.bdd.var(f"rc_{value}") for value in cube.resource_class])
        )
    if cube.target_zone:
        parts.append(env._or([env.bdd.var(f"tz_{value}") for value in cube.target_zone]))
    for flag in cube.flag_true:
        parts.append(env.bdd.var(f"flag_{flag}"))
    for flag in cube.flag_false:
        parts.append(~env.bdd.var(f"flag_{flag}"))
    return env._and(parts) if parts else env.bdd.true


def generalize(env: BDDEnv, seed: State, target) -> Cube | None:
    cube = state_to_full_cube(seed)
    seed_node = cube_to_bdd(env, cube) & env.valid
    if env.count(seed_node & target) == 0:
        return None

    for flag in ALL_FLAGS:
        relaxed = _drop_flag(cube, flag)
        if relaxed is not None and _is_useful_subset(env, relaxed, target):
            cube = relaxed

    for dimension in ("target_zone", "resource_class", "operation"):
        relaxed = cube.model_copy(update={dimension: [], "size": 0})
        relaxed = _with_size(relaxed)
        if _is_useful_subset(env, relaxed, target):
            cube = relaxed

    if literal_count(cube) <= MAX_LITERALS:
        return _with_size(cube)

    return _largest_three_literal_subset(env, cube, target)


def _drop_flag(cube: Cube, flag: str) -> Cube | None:
    if flag in cube.flag_true:
        flag_true = [item for item in cube.flag_true if item != flag]
        return _with_size(cube.model_copy(update={"flag_true": flag_true, "size": 0}))
    if flag in cube.flag_false:
        flag_false = [item for item in cube.flag_false if item != flag]
        return _with_size(cube.model_copy(update={"flag_false": flag_false, "size": 0}))
    return None


def _is_useful_subset(env: BDDEnv, cube: Cube, target) -> bool:
    node = cube_to_bdd(env, cube) & env.valid
    return env.count(node & ~target) == 0 and env.count(node & target) > 0


def _largest_three_literal_subset(env: BDDEnv, cube: Cube, target) -> Cube | None:
    best: Cube | None = None
    for literals in combinations(_literals(cube), MAX_LITERALS):
        candidate = _cube_from_literals(literals)
        if not _is_useful_subset(env, candidate, target):
            continue
        if best is None or candidate.size > best.size:
            best = candidate
    return best


def _literals(cube: Cube) -> list[tuple[str, list[str] | str]]:
    literals: list[tuple[str, list[str] | str]] = []
    if cube.operation:
        literals.append(("operation", cube.operation))
    if cube.resource_class:
        literals.append(("resource_class", cube.resource_class))
    if cube.target_zone:
        literals.append(("target_zone", cube.target_zone))
    literals.extend(("flag_true", flag) for flag in cube.flag_true)
    literals.extend(("flag_false", flag) for flag in cube.flag_false)
    return literals


def _cube_from_literals(literals: tuple[tuple[str, list[str] | str], ...]) -> Cube:
    operation: list[str] = []
    resource_class: list[str] = []
    target_zone: list[str] = []
    flag_true: list[str] = []
    flag_false: list[str] = []
    for kind, value in literals:
        if kind == "operation":
            operation = list(value)
        elif kind == "resource_class":
            resource_class = list(value)
        elif kind == "target_zone":
            target_zone = list(value)
        elif kind == "flag_true":
            flag_true.append(str(value))
        elif kind == "flag_false":
            flag_false.append(str(value))
    return _with_size(
        Cube(
            operation=operation,
            resource_class=resource_class,
            target_zone=target_zone,
            flag_true=sorted(flag_true),
            flag_false=sorted(flag_false),
            size=0,
        )
    )


def _with_size(cube: Cube) -> Cube:
    return cube.model_copy(update={"size": cube_size(cube)})
