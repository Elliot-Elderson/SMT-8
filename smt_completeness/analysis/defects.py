from pydantic import BaseModel

from ..bdd_env import BDDEnv
from ..ir import DECISION_KINDS, Policy, Rule, RuleKind
from ..state_space import State
from ..vocab import Operation, ResourceClass, TargetZone
from .consistency import state_to_dict


class DeadClause(BaseModel):
    rule_id: str
    kind: RuleKind
    hit_volume: int
    covering_rule_ids: list[str]


class OverlapRatio(BaseModel):
    rule_id: str
    kind: RuleKind
    hit_volume: int
    effective_volume: int


class DefectReport(BaseModel):
    silent_permission_volume: int
    silent_permission_states: list[dict]
    dead_clauses: list[DeadClause]
    precedence_overlap_volume: int
    overlap_ratios: list[OverlapRatio]


def _default_allow_states() -> list[State]:
    return [
        State(operation, resource_class, TargetZone.LOCAL, frozenset())
        for operation in (Operation.READ, Operation.LIST)
        for resource_class in ResourceClass
    ]


def silent_permission_states(policy: Policy) -> list[State]:
    decision_rules = [rule for rule in policy.rules if rule.kind in DECISION_KINDS]
    return [
        state
        for state in _default_allow_states()
        if not any(rule.condition.matches(state) for rule in decision_rules)
    ]


def _effective_bdd(env: BDDEnv, rule: Rule):
    matched = env.match_rule(rule) & env.valid
    if rule.kind == RuleKind.MANDATORY_DENY:
        return matched
    if rule.kind == RuleKind.MUST_CHALLENGE:
        return matched & ~env._kind(RuleKind.MANDATORY_DENY)
    if rule.kind == RuleKind.MAY_ALLOW:
        return (
            matched
            & ~env._kind(RuleKind.MANDATORY_DENY)
            & ~env._kind(RuleKind.MUST_CHALLENGE)
        )
    return env.bdd.false


def _covering_kinds(kind: RuleKind) -> list[RuleKind]:
    if kind == RuleKind.MUST_CHALLENGE:
        return [RuleKind.MANDATORY_DENY]
    if kind == RuleKind.MAY_ALLOW:
        return [RuleKind.MANDATORY_DENY, RuleKind.MUST_CHALLENGE]
    return []


def _covering_rule_ids(env: BDDEnv, rule: Rule) -> list[str]:
    kinds = _covering_kinds(rule.kind)
    if not kinds:
        return []
    hit = env.valid & env.match_rule(rule)
    ids: list[str] = []
    for other in env.policy.rules:
        if other.id == rule.id or other.kind not in kinds:
            continue
        if env.count(hit & env.match_rule(other)) > 0:
            ids.append(other.id)
    return ids


def check_defects(policy: Policy) -> DefectReport:
    env = BDDEnv(policy)
    silent = silent_permission_states(policy)
    deny = env._kind(RuleKind.MANDATORY_DENY)
    challenge = env._kind(RuleKind.MUST_CHALLENGE)
    dead_clauses: list[DeadClause] = []
    overlap_ratios: list[OverlapRatio] = []
    for rule in policy.rules:
        if rule.kind not in DECISION_KINDS:
            continue
        hit_volume = env.count(env.valid & env.match_rule(rule))
        effective_volume = env.count(_effective_bdd(env, rule))
        overlap_ratios.append(
            OverlapRatio(
                rule_id=rule.id,
                kind=rule.kind,
                hit_volume=hit_volume,
                effective_volume=effective_volume,
            )
        )
        if effective_volume == 0 and hit_volume > 0:
            dead_clauses.append(
                DeadClause(
                    rule_id=rule.id,
                    kind=rule.kind,
                    hit_volume=hit_volume,
                    covering_rule_ids=_covering_rule_ids(env, rule),
                )
            )
    return DefectReport(
        silent_permission_volume=len(silent),
        silent_permission_states=[state_to_dict(state) for state in silent],
        dead_clauses=dead_clauses,
        precedence_overlap_volume=env.count(env.valid & deny & challenge),
        overlap_ratios=overlap_ratios,
    )
