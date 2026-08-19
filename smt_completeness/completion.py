from pydantic import BaseModel

from .analysis.coverage import Cube, check_coverage
from .compiler import decide_py
from .ir import Condition, Policy, Priority, Provenance, Rule, RuleKind
from .state_space import all_states
from .vocab import Decision, Operation, ResourceClass, TargetZone


def synthesize_rule_for_cube(cube: Cube, idx: int) -> Rule:
    """分析器持有安全逻辑：把危险面 cube 提升为 mandatory_deny 候选。"""
    cond = Condition(
        operation=[Operation(o) for o in cube.operation],
        resource_class=[ResourceClass(r) for r in cube.resource_class],
        target_zone=[TargetZone(t) for t in cube.target_zone],
        flag_true=list(cube.flag_true),
        flag_false=list(cube.flag_false),
    )
    return Rule(
        id=f"LLM-{idx}",
        source_anchor="LLM 补全（危险面 cube）",
        kind=RuleKind.MANDATORY_DENY,
        condition=cond,
        decision=Decision.DENY,
        priority=Priority.MANDATORY,
        extraction_confidence="medium",
        reviewer_status="auto_approved",
        provenance=Provenance.LLM_SYNTHESIZED,
    )


def render_chinese(rule: Rule, use_llm: bool = False) -> str:
    """离线模板渲染（demo 默认）；use_llm 预留给 instructor 路径。"""
    c = rule.condition
    op = "、".join(o.value for o in c.operation) or "任意操作"
    rc = "、".join(r.value for r in c.resource_class) or "任意资源"
    tz = "、".join(t.value for t in c.target_zone) or "任意目标"
    return f"禁止对【{rc}】在【{tz}】执行【{op}】（补全自危险面盲区）。"


def verify_monotone(old: Policy, new: Policy) -> bool:
    """∀s. D_new(s) >= D_old(s)：只收紧不放宽。"""
    for state in all_states():
        if int(decide_py(state, new)) < int(decide_py(state, old)):
            return False
    return True


class CompletionRound(BaseModel):
    round_index: int
    v_danger_before: int
    v_danger_after: int
    added_rule_ids: list[str]
    monotone_ok: bool


class CompletionResult(BaseModel):
    rounds: list[CompletionRound]
    final_policy: Policy
    converged: bool
    manual_review_todos: list[str]


def run_completion(policy: Policy, max_rounds: int = 5) -> CompletionResult:
    """Run monotonic closed-loop completion without a human review UI."""
    current = policy
    rounds: list[CompletionRound] = []
    todos: list[str] = []
    converged = False
    rule_counter = 0

    for i in range(max_rounds):
        cov_before = check_coverage(current)
        if cov_before.v_danger == 0:
            converged = True
            break

        added_ids: list[str] = []
        candidate_rules = list(current.rules)
        for cube in cov_before.danger_cubes:
            rule_counter += 1
            new_rule = synthesize_rule_for_cube(cube, rule_counter)
            candidate_rules.append(new_rule)
            added_ids.append(new_rule.id)
        candidate = Policy(rules=candidate_rules)

        monotone_ok = verify_monotone(current, candidate)
        cov_after = check_coverage(candidate) if monotone_ok else cov_before

        rounds.append(
            CompletionRound(
                round_index=i,
                v_danger_before=cov_before.v_danger,
                v_danger_after=cov_after.v_danger,
                added_rule_ids=added_ids if monotone_ok else [],
                monotone_ok=monotone_ok,
            )
        )

        if not monotone_ok:
            todos.append(f"第 {i} 轮候选未通过单调性验证，需人工介入。")
            break
        if cov_after.v_danger >= cov_before.v_danger:
            todos.append(
                f"第 {i} 轮 V_danger 未改善（{cov_before.v_danger}→{cov_after.v_danger}），停止闭环，需人工介入。"
            )
            current = candidate
            break

        current = candidate
        if cov_after.v_danger == 0:
            converged = True
            break

    return CompletionResult(
        rounds=rounds,
        final_policy=current,
        converged=converged,
        manual_review_todos=todos,
    )
