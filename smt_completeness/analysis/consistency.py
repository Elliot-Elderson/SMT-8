import z3
from pydantic import BaseModel

from ..compiler import build_env, find_witness
from ..ir import Policy, RuleKind
from ..state_space import State, all_states


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
    Python 枚举精确计数；Z3 拿反例；两者对账。
    """
    deny_rules = [r for r in policy.rules_of_kind(RuleKind.MANDATORY_DENY)]
    chal_rules = [r for r in policy.rules_of_kind(RuleKind.MUST_CHALLENGE)]

    # Python 枚举计数
    count = 0
    py_example = None
    for s in all_states():
        d_hit = any(r.condition.matches(s) for r in deny_rules)
        c_hit = any(r.condition.matches(s) for r in chal_rules)
        if d_hit and c_hit:
            count += 1
            if py_example is None:
                py_example = s

    # Z3 反例
    def constraint(env):
        deny_expr = z3.Or([env.match_expr(r) for r in deny_rules]) if deny_rules else z3.BoolVal(False)
        chal_expr = z3.Or([env.match_expr(r) for r in chal_rules]) if chal_rules else z3.BoolVal(False)
        return z3.And(deny_expr, chal_expr)

    z3_example = find_witness(policy, constraint)

    # 对账：两条路径必须一致
    assert (count > 0) == (z3_example is not None), \
        f"C3 对账失败：枚举 count={count} 与 Z3 witness={z3_example} 不一致"

    if py_example:
        deny_ids = [r.id for r in deny_rules if r.condition.matches(py_example)]
        chal_ids = [r.id for r in chal_rules if r.condition.matches(py_example)]
    else:
        deny_ids = []
        chal_ids = []

    example = state_to_dict(py_example) if py_example else None
    return ConflictReport(
        overlap_count=count,
        example_state=example,
        deny_rule_ids=deny_ids,
        challenge_rule_ids=chal_ids,
    )
