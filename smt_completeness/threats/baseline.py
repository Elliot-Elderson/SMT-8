import os
from typing import Literal

import yaml
from pydantic import BaseModel

from ..analysis.consistency import state_to_dict
from ..compiler import decide_py
from ..ir import Condition, Policy
from ..state_space import all_states

_DEFAULT_SEED = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "threat_seed.yaml")
)


class ThreatInvariant(BaseModel):
    id: str
    source: str
    desc: str
    expressible: bool
    precondition: Condition
    min_decision: int
    prejudgment: str


class GapItem(BaseModel):
    id: str
    source: str
    desc: str
    kind: Literal["requirement_gap", "vocab_gap"]
    example_state: dict | None


class BaselineReport(BaseModel):
    total: int
    covered: int
    requirement_gaps: int
    vocab_gaps: int
    coverage_ratio: float
    gaps: list[GapItem]


def load_seed(path: str | None = None) -> list[ThreatInvariant]:
    seed_path = path or _DEFAULT_SEED
    with open(seed_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return [ThreatInvariant(**item) for item in data["invariants"]]


def check_baseline(
    policy: Policy, seed: list[ThreatInvariant] | None = None
) -> BaselineReport:
    invariants = load_seed() if seed is None else seed
    covered = 0
    gaps: list[GapItem] = []

    for invariant in invariants:
        if not invariant.expressible:
            gaps.append(
                GapItem(
                    id=invariant.id,
                    source=invariant.source,
                    desc=invariant.desc,
                    kind="vocab_gap",
                    example_state=None,
                )
            )
            continue

        example_state = None
        for state in all_states():
            if invariant.precondition.matches(state) and int(decide_py(state, policy)) < invariant.min_decision:
                example_state = state
                break

        if example_state is None:
            covered += 1
            continue

        gaps.append(
            GapItem(
                id=invariant.id,
                source=invariant.source,
                desc=invariant.desc,
                kind="requirement_gap",
                example_state=state_to_dict(example_state),
            )
        )

    requirement_gaps = sum(1 for gap in gaps if gap.kind == "requirement_gap")
    vocab_gaps = sum(1 for gap in gaps if gap.kind == "vocab_gap")
    total = len(invariants)
    coverage_ratio = covered / total if total else 0.0
    return BaselineReport(
        total=total,
        covered=covered,
        requirement_gaps=requirement_gaps,
        vocab_gaps=vocab_gaps,
        coverage_ratio=coverage_ratio,
        gaps=gaps,
    )
