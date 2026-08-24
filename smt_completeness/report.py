import os

from pydantic import BaseModel

from .analysis.consistency import ConflictReport, check_consistency
from .analysis.coverage import CoverageReport, check_coverage
from .analysis.monotonicity import MonotonicityReport, check_monotonicity
from .analysis.redundancy import RedundancyReport, check_redundancy
from .analysis.tightening import TighteningReport, check_tightening
from .compiler import export_smtlib
from .completion import CompletionResult
from .extractor import SelfCheckReport, self_check
from .ir import Policy
from .vocab import ALL_FLAGS

ASSUMPTIONS = [
    "A1 不引入 tool 维度——文档所有规则按操作与风险特征表述。",
    "A2 资源分类器完美（布尔抽象）——路径变形绕过原型阶段不可见。",
    "A3 MustAllow 推导正确（§5 减 §3、§4）——决定可收紧性结论强度上限。",
    "A4 H1 只覆盖规则级收紧——H1 tight ≠ 绝对 tight。",
    "A5 敏感度偏序从章节顺序推导——需人工复核该算子每个输出。",
    "A7 需求集不含管理性语义（委派/角色授予）——否则落入 HRU 不可判定区。",
    "A8 本期不使用外部威胁宇宙，内部指标不声称外部攻击覆盖。",
]


class FullReport(BaseModel):
    self_check: SelfCheckReport
    consistency: ConflictReport
    redundancy: RedundancyReport
    coverage: CoverageReport
    tightening: TighteningReport
    monotonicity: MonotonicityReport
    assumptions: list[str]


def build_report(policy: Policy) -> FullReport:
    return FullReport(
        self_check=self_check(policy),
        consistency=check_consistency(policy),
        redundancy=check_redundancy(policy),
        coverage=check_coverage(policy),
        tightening=check_tightening(policy),
        monotonicity=check_monotonicity(policy),
        assumptions=ASSUMPTIONS,
    )


def _format_cube_value(values: list[str]) -> str:
    return ",".join(values) if values else "*"


def _format_metric(value: int, ratio: float | None = None) -> str:
    if ratio is None:
        return str(value)
    return f"{value}（{ratio:.2%}）"


def _format_cube(cube) -> str:
    dc_flags = sorted(
        f for f in ALL_FLAGS if f not in cube.flag_true and f not in cube.flag_false
    )
    dc_part = f" dc={_format_cube_value(dc_flags)}" if dc_flags else ""
    return (
        f"op={_format_cube_value(cube.operation)} "
        f"rc={_format_cube_value(cube.resource_class)} "
        f"zone={_format_cube_value(cube.target_zone)} "
        f"flag_true={_format_cube_value(cube.flag_true)} "
        f"flag_false={_format_cube_value(cube.flag_false)}"
        f"{dc_part} size={cube.size}"
    )


def _compare_row(name: str, before: object, after: object) -> str:
    return f"| {name} | {before} | {after} |"


def _completion_totals(completion: CompletionResult) -> dict[str, int | bool]:
    return {
        "rounds": len(completion.rounds),
        "converged": completion.converged,
        "added": sum(len(round.added_rule_ids) for round in completion.rounds),
        "removed": sum(len(round.removed_rule_ids) for round in completion.rounds),
        "narrowed": sum(len(round.narrowed_rule_ids) for round in completion.rounds),
        "skipped": sum(len(round.skipped) for round in completion.rounds),
    }


def render_markdown(
    report: FullReport,
    *,
    label: str,
    compare: FullReport | None = None,
    completion: CompletionResult | None = None,
) -> str:
    c = report.coverage
    lines: list[str] = []

    lines.append(f"# Agent 访问控制需求完备性评测报告（{label}）\n")
    lines.append("## 1. 概览\n")
    lines.append(f"- 规则总数：{report.self_check.total_rules}")
    lines.append(
        f"- 自动自检：{'通过' if report.self_check.ok else '未通过'}"
        f"（id 唯一={report.self_check.id_unique}，"
        f"恒假规则={report.self_check.vacuous_rule_ids}）"
    )
    lines.append(f"- 显式规则命中体积：{_format_metric(c.v_explicit, c.v_explicit_ratio)}")
    lines.append(f"- 未表态体积：{_format_metric(c.v_unspecified, c.v_unspecified_ratio)}")
    lines.append("")

    lines.append("## 2. 表达力与未表态\n")
    lines.append(f"- 状态空间总数：{c.total}")
    lines.append(f"- V_explicit（显式覆盖，策略表达力）：{c.v_explicit}（{c.v_explicit_ratio:.2%}）")
    lines.append(f"- V_unspecified（未显式表态）：{c.v_unspecified}（{c.v_unspecified_ratio:.2%}）")
    lines.append(f"- V_unspecified_allow（未表态且默认 Allow）：{c.v_unspecified_allow}（{c.v_unspecified_allow_ratio:.2%}）")
    lines.append(f"- V_unspecified_challenge（未表态且默认 Challenge）：{c.v_unspecified_challenge}（{c.v_unspecified_challenge_ratio:.2%}）")
    lines.append("")
    lines.append("### 未表态（无显式规则命中）\n")
    lines.append("V_unspecified_challenge 是旧称对 LLM 兜底体积。")
    lines.append("")

    lines.append("## 3. 可补全反例（倒挂例子）\n")
    lines.append(f"- 严格偏序倒挂数：{report.monotonicity.inversion_count}")
    lines.append(f"- 同级保护不对称数：{report.monotonicity.equal_rank_asymmetry_count}")
    for ex in report.monotonicity.inversion_examples[:5]:
        lines.append(
            f"  - 高={ex.high_state} D={ex.high_decision} "
            f"vs 低={ex.low_state} D={ex.low_decision}"
        )
    for ex in report.monotonicity.equal_rank_examples[:5]:
        lines.append(
            f"  - 同级 A={ex.high_state} D={ex.high_decision} "
            f"vs B={ex.low_state} D={ex.low_decision}"
        )
    if c.unspecified_cubes:
        lines.append("\n### 未表态 cube（Top 10）\n")
        for cube in c.unspecified_cubes[:10]:
            lines.append(f"- {_format_cube(cube)}")
        lines.append("")

    lines.append("## 4. 卫生 C3/C4\n")
    lines.append(f"- mandatory 重叠（challenge 被 deny 掩盖）状态数：{report.consistency.overlap_count}")
    if report.consistency.example_state:
        lines.append(f"  - 示例：{report.consistency.example_state}")
    lines.append(f"- 冗余规则：{report.redundancy.redundant_rule_ids or '无'}")
    lines.append("")

    lines.append("## 5. H1 参考\n")
    lines.append(f"- 是否 H1 tight（相对规则级收紧空间）：{report.tightening.is_h1_tight}")
    lines.append(f"- 可收紧规则：{report.tightening.tightenable_rule_ids or '无'}")
    lines.append("")

    if compare is not None:
        before = compare
        after = report
        lines.append("## 6. 补全前后对照\n")
        lines.append("| 指标 | before | after |")
        lines.append("| --- | ---: | ---: |")
        lines.append(_compare_row("倒挂数", before.monotonicity.inversion_count, after.monotonicity.inversion_count))
        lines.append(_compare_row("同级不对称", before.monotonicity.equal_rank_asymmetry_count, after.monotonicity.equal_rank_asymmetry_count))
        lines.append(_compare_row("V_unspecified", before.coverage.v_unspecified, after.coverage.v_unspecified))
        lines.append(_compare_row("V_unspecified_allow", before.coverage.v_unspecified_allow, after.coverage.v_unspecified_allow))
        lines.append(_compare_row("V_unspecified_challenge", before.coverage.v_unspecified_challenge, after.coverage.v_unspecified_challenge))
        lines.append(_compare_row("V_explicit", before.coverage.v_explicit, after.coverage.v_explicit))
        lines.append(_compare_row("C3", before.consistency.overlap_count, after.consistency.overlap_count))
        lines.append(_compare_row("规则数", before.self_check.total_rules, after.self_check.total_rules))
        lines.append("")
        if completion is not None:
            totals = _completion_totals(completion)
            lines.append("### 补全摘要\n")
            lines.append(f"- 轮次：{totals['rounds']}")
            lines.append(f"- 收敛：{totals['converged']}")
            lines.append(f"- 新增规则：{totals['added']}")
            lines.append(f"- 删除规则：{totals['removed']}")
            lines.append(f"- 收窄规则：{totals['narrowed']}")
            lines.append(f"- 跳过：{totals['skipped']}")
            lines.append("")

    assumption_section = "## 7. 假设\n" if compare is not None else "## 6. 假设\n"
    lines.append(assumption_section)
    for assumption in report.assumptions:
        lines.append(f"- {assumption}")
    lines.append("")

    return "\n".join(lines)


def write_policy_reports(
    policy: Policy,
    out_dir: str,
    stem: str,
    report: "FullReport | None" = None,
) -> tuple[str, str, str]:
    os.makedirs(out_dir, exist_ok=True)
    # Always build internally so Z3 state is equivalent to the original call sequence.
    # If the caller already has an analysed report, use that for file output so that
    # the written MD and JSON come from the same analysis object.
    built = build_report(policy)
    used_report = report if report is not None else built
    md_path = os.path.join(out_dir, f"{stem}.md")
    json_path = os.path.join(out_dir, f"{stem}.json")
    smt_path = os.path.join(out_dir, f"policy_{stem}.smt2")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(used_report, label=stem))
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(used_report.model_dump_json(indent=2))
    export_smtlib(policy, smt_path)

    return md_path, json_path, smt_path


def write_reports(policy: Policy, out_dir: str) -> tuple[str, str, str]:
    return write_policy_reports(policy, out_dir, "report")
