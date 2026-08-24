from pydantic import BaseModel

from ..compiler import policies_equivalent
from ..ir import Policy


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
