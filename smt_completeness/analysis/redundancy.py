from pydantic import BaseModel

from ..bdd_env import BDDEnv
from ..compiler import policies_equivalent
from ..ir import DECISION_KINDS, Policy


class RedundancyReport(BaseModel):
    redundant_rule_ids: list[str]
    total_rules: int


def _policy_equivalent(a: Policy, b: Policy) -> bool:
    return policies_equivalent(a, b)


def check_redundancy(policy: Policy) -> RedundancyReport:
    """Greedy fixation: remove one equivalent rule, commit it, then continue."""
    kept = list(policy.rules)
    removed_ids: list[str] = []
    i = 0

    while i < len(kept):
        candidate = kept[i]
        trial = Policy(rules=[rule for j, rule in enumerate(kept) if j != i])
        if _policy_equivalent(Policy(rules=kept), trial):
            removed_ids.append(candidate.id)
            kept = trial.rules
        else:
            i += 1

    return RedundancyReport(
        redundant_rule_ids=removed_ids,
        total_rules=len(policy.rules),
    )


def check_duplicates(policy: Policy) -> list[str]:
    env = BDDEnv(policy)
    duplicates: list[str] = []
    for rule in policy.rules:
        if rule.kind not in DECISION_KINDS:
            continue
        others = [
            env.match_rule(other)
            for other in policy.rules
            if other.id != rule.id and other.kind == rule.kind
        ]
        if not others:
            continue
        union = others[0]
        for node in others[1:]:
            union = union | node
        hit = env.valid & env.match_rule(rule)
        if env.count(hit) == 0:
            continue
        if env.count(hit & ~union) == 0:
            duplicates.append(rule.id)
    return duplicates
