from dataclasses import dataclass
from itertools import chain, combinations, product
from typing import Iterator

from .vocab import ALL_FLAGS, Operation, ResourceClass, TargetZone

EXPECTED_STATE_COUNT = len(Operation) * len(ResourceClass) * len(TargetZone) * (2 ** len(ALL_FLAGS))


@dataclass(frozen=True)
class State:
    operation: Operation
    resource_class: ResourceClass
    target_zone: TargetZone
    flags: frozenset  # frozenset[str] ⊆ ALL_FLAGS


def _flag_subsets() -> Iterator[frozenset]:
    for r in range(len(ALL_FLAGS) + 1):
        for combo in combinations(ALL_FLAGS, r):
            yield frozenset(combo)


def all_states() -> Iterator[State]:
    # 调试专用：完整枚举 122880 个合法状态。生产代码禁止调用（改用 BDDEnv / Z3 分析）。
    for op, rc, tz, flags in product(
        Operation, ResourceClass, TargetZone, _flag_subsets()
    ):
        yield State(op, rc, tz, flags)


def state_count() -> int:
    return EXPECTED_STATE_COUNT
