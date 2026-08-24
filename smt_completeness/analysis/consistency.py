import z3
from pydantic import BaseModel

from ..bdd_env import BDDEnv
from ..compiler import find_witness
from ..ir import Policy, RuleKind
from ..state_space import State


def state_to_dict(state: State) -> dict:
    return {
        "operation": state.operation.value,
        "resource_class": state.resource_class.value,
        "target_zone": state.target_zone.value,
        "flags": sorted(state.flags),
    }


class ConflictReport(BaseModel):
    overlap_count: int
    example_state: dict | None
    deny_rule_ids: list[str]
    challenge_rule_ids: list[str]


def check_consistency(policy: Policy) -> ConflictReport:
    """spec §5.1：真冲突 = 同为 mandatory 优先级但效果不同的规则共同命中。
    本 demo 检测 mandatory_deny 与 must_challenge 的重叠（challenge 被 deny 掩盖）。
    BDD 精确计数；Z3 拿反例；两者对账。
    """
    deny_rules = [r for r in policy.rules_of_kind(RuleKind.MANDATORY_DENY)]
    chal_rules = [r for r in policy.rules_of_kind(RuleKind.MUST_CHALLENGE)]

    env_b = BDDEnv(policy)
    deny = env_b._kind(RuleKind.MANDATORY_DENY)
    chal = env_b._kind(RuleKind.MUST_CHALLENGE)
    count = env_b.count(env_b.valid & deny & chal)

    # Z3 反例
    def constraint(env):
        return z3.And(
            env._kind_or(RuleKind.MANDATORY_DENY),
            env._kind_or(RuleKind.MUST_CHALLENGE),
        )

    z3_example = find_witness(policy, constraint)

    # 对账：两条路径必须一致
    assert (count > 0) == (z3_example is not None), \
        f"C3 对账失败：BDD count={count} 与 Z3 witness={z3_example} 不一致"

    if z3_example:
        deny_ids = [r.id for r in deny_rules if r.condition.matches(z3_example)]
        chal_ids = [r.id for r in chal_rules if r.condition.matches(z3_example)]
    else:
        deny_ids = []
        chal_ids = []

    example = state_to_dict(z3_example) if z3_example else None
    return ConflictReport(
        overlap_count=count,
        example_state=example,
        deny_rule_ids=deny_ids,
        challenge_rule_ids=chal_ids,
    )
