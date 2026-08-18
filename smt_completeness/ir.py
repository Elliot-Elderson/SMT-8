from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .state_space import State
from .vocab import ALL_FLAGS, Decision, Operation, ResourceClass, TargetZone


class RuleKind(str, Enum):
    MANDATORY_DENY = "mandatory_deny"
    MUST_CHALLENGE = "must_challenge"
    MAY_ALLOW = "may_allow"
    RESOURCE_DEF = "resource_def"
    LIMITATION = "limitation"


class Priority(str, Enum):
    MANDATORY = "mandatory"
    LEARNED = "learned"
    DEFAULT = "default"


class Provenance(str, Enum):
    EXTRACTED = "extracted"
    LLM_SYNTHESIZED = "llm_synthesized"


class Condition(BaseModel):
    operation: list[Operation] = Field(default_factory=list)
    resource_class: list[ResourceClass] = Field(default_factory=list)
    target_zone: list[TargetZone] = Field(default_factory=list)
    flag_true: list[str] = Field(default_factory=list)
    flag_false: list[str] = Field(default_factory=list)

    @field_validator("flag_true", "flag_false")
    @classmethod
    def _flags_in_vocab(cls, v: list[str]) -> list[str]:
        bad = [f for f in v if f not in ALL_FLAGS]
        if bad:
            raise ValueError(
                f"未知 flag: {bad}；合法取值仅限 {ALL_FLAGS}。请从该清单中选择。"
            )
        return v

    def matches(self, state: State) -> bool:
        if self.operation and state.operation not in self.operation:
            return False
        if self.resource_class and state.resource_class not in self.resource_class:
            return False
        if self.target_zone and state.target_zone not in self.target_zone:
            return False
        if any(f not in state.flags for f in self.flag_true):
            return False
        if any(f in state.flags for f in self.flag_false):
            return False
        return True


class Rule(BaseModel):
    id: str
    source_anchor: str
    kind: RuleKind
    condition: Condition
    decision: Decision
    priority: Priority
    extraction_confidence: Literal["high", "medium", "low"]
    reviewer_status: str = "auto_approved"
    provenance: Provenance = Provenance.EXTRACTED


class Policy(BaseModel):
    rules: list[Rule] = Field(default_factory=list)

    def rules_of_kind(self, kind: RuleKind) -> list[Rule]:
        return [r for r in self.rules if r.kind == kind]
