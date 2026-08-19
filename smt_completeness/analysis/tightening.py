from pydantic import BaseModel

from ..compiler import decide_py, must_allow
from ..ir import Policy, RuleKind
from ..state_space import all_states
from ..vocab import Decision


class TighteningReport(BaseModel):
    tightenable_rule_ids: list[str]
    witnessed_rule_ids: list[str]
    is_h1_tight: bool


def _raise_rule(policy: Policy, rule_id: str) -> Policy:
    new_rules = []
    for rule in policy.rules:
        if rule.id == rule_id and rule.decision < Decision.DENY:
            raised = rule.model_copy(deep=True)
            raised.decision = Decision(int(rule.decision) + 1)
            if raised.decision == Decision.CHALLENGE:
                raised.kind = RuleKind.MUST_CHALLENGE
            elif raised.decision == Decision.DENY:
                raised.kind = RuleKind.MANDATORY_DENY
            new_rules.append(raised)
        else:
            new_rules.append(rule)
    return Policy(rules=new_rules)


def check_tightening(policy: Policy) -> TighteningReport:
    """spec §5.4 H1: a rule is tightenable if raising it preserves MustAllow."""
    mustallow_states = [state for state in all_states() if must_allow(state, policy)]
    tightenable_rule_ids: list[str] = []
    witnessed_rule_ids: list[str] = []

    for rule in policy.rules:
        if rule.decision >= Decision.DENY:
            continue
        if rule.kind not in (RuleKind.MAY_ALLOW, RuleKind.MUST_CHALLENGE):
            continue

        raised_policy = _raise_rule(policy, rule.id)
        breaks_mustallow = any(
            decide_py(state, raised_policy) != Decision.ALLOW
            for state in mustallow_states
        )
        if breaks_mustallow:
            witnessed_rule_ids.append(rule.id)
        else:
            tightenable_rule_ids.append(rule.id)

    return TighteningReport(
        tightenable_rule_ids=tightenable_rule_ids,
        witnessed_rule_ids=witnessed_rule_ids,
        is_h1_tight=(len(tightenable_rule_ids) == 0),
    )
