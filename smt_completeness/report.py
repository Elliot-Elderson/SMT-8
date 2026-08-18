import os

from pydantic import BaseModel

from .analysis.consistency import ConflictReport, check_consistency
from .analysis.coverage import CoverageReport, check_coverage
from .analysis.monotonicity import MonotonicityReport, check_monotonicity
from .analysis.redundancy import RedundancyReport, check_redundancy
from .analysis.tightening import TighteningReport, check_tightening
from .compiler import export_smtlib
from .extractor import SelfCheckReport, self_check
from .ir import Policy
from .vocab import ALL_FLAGS
from .threats.baseline import BaselineReport, check_baseline

ASSUMPTIONS = [
    "A1 不引入 tool 维度——文档所有规则按操作与风险特征表述。",
    "A2 资源分类器完美（布尔抽象）——路径变形绕过原型阶段不可见。",
    "A3 MustAllow 推导正确（§5 减 §3、§4）——决定可收紧性结论强度上限。",
    "A4 H1 只覆盖规则级收紧——H1 tight ≠ 绝对 tight。",
    "A5 敏感度偏序从章节顺序推导——需人工复核该算子每个输出。",
    "A6 威胁种子表质量决定覆盖率强度——种子为人工初判，需逐条复核。",
    "A7 需求集不含管理性语义（委派/角色授予）——否则落入 HRU 不可判定区。",
]


class FullReport(BaseModel):
    self_check: SelfCheckReport
    consistency: ConflictReport
    redundancy: RedundancyReport
    coverage: CoverageReport
    tightening: TighteningReport
    monotonicity: MonotonicityReport
    baseline: BaselineReport
    assumptions: list[str]


def build_report(policy: Policy) -> FullReport:
    return FullReport(
        self_check=self_check(policy),
        consistency=check_consistency(policy),
        redundancy=check_redundancy(policy),
        coverage=check_coverage(policy),
        tightening=check_tightening(policy),
        monotonicity=check_monotonicity(policy),
        baseline=check_baseline(policy),
        assumptions=ASSUMPTIONS,
    )


def _format_cube_value(values: list[str]) -> str:
    return ",".join(values) if values else "*"


def render_markdown(report: FullReport) -> str:
    c = report.coverage
    b = report.baseline
    lines: list[str] = []

    lines.append("# Agent 访问控制需求完备性评测报告\n")
    lines.append("## 1. 概览\n")
    lines.append(f"- 规则总数：{report.self_check.total_rules}")
    lines.append(
        f"- 自动自检：{'通过' if report.self_check.ok else '未通过'}"
        f"（id 唯一={report.self_check.id_unique}，"
        f"恒假规则={report.self_check.vacuous_rule_ids}）"
    )
    lines.append("")

    lines.append("## 2. 三分区体积（C2）\n")
    lines.append(f"- 状态空间总数：{c.total}")
    lines.append(f"- V_explicit（显式覆盖，策略表达力）：{c.v_explicit}（{c.v_explicit_ratio:.2%}）")
    lines.append(f"- **V_danger（默认放行，真实攻击面）：{c.v_danger}（{c.v_danger_ratio:.2%}）**")
    lines.append(
        f"- V_deferred（默认 Challenge，对 LLM 的依赖度）："
        f"{c.v_deferred}（{c.v_deferred_ratio:.2%}）"
    )
    lines.append("")

    if c.danger_cubes:
        lines.append("### 危险面待补 cube（Top 10）\n")
        for cube in c.danger_cubes[:10]:
            dc_flags = sorted(
                f for f in ALL_FLAGS
                if f not in cube.flag_true and f not in cube.flag_false
            )
            dc_part = f" dc={_format_cube_value(dc_flags)}" if dc_flags else ""
            lines.append(
                f"- op={_format_cube_value(cube.operation)} "
                f"rc={_format_cube_value(cube.resource_class)} "
                f"zone={_format_cube_value(cube.target_zone)} "
                f"flag_true={_format_cube_value(cube.flag_true)} "
                f"flag_false={_format_cube_value(cube.flag_false)}"
                f"{dc_part} size={cube.size}"
            )
        lines.append("")

    lines.append("## 3. 一致性与冗余（C3/C4）\n")
    lines.append(f"- mandatory 重叠（challenge 被 deny 掩盖）状态数：{report.consistency.overlap_count}")
    if report.consistency.example_state:
        lines.append(f"  - 示例：{report.consistency.example_state}")
    lines.append(f"- 冗余规则：{report.redundancy.redundant_rule_ids or '无'}")
    lines.append("")

    lines.append("## 4. 可收紧性（C1 · H1）\n")
    lines.append(f"- 是否 H1 tight（相对规则级收紧空间）：{report.tightening.is_h1_tight}")
    lines.append(f"- 可收紧规则：{report.tightening.tightenable_rule_ids or '无'}")
    lines.append("")

    lines.append("## 5. 敏感度单调性\n")
    lines.append(f"- 严格偏序倒挂数：{report.monotonicity.inversion_count}")
    lines.append(f"- 同级保护不对称数：{report.monotonicity.equal_rank_asymmetry_count}")
    for ex in report.monotonicity.equal_rank_examples[:5]:
        lines.append(
            f"  - 高={ex.high_state} D={ex.high_decision} "
            f"vs 低={ex.low_state} D={ex.low_decision}"
        )
    lines.append("")

    lines.append("## 6. 外部威胁基线对照\n")
    lines.append(f"- **威胁覆盖率：{b.coverage_ratio:.2%}（{b.covered}/{b.total}）**")
    lines.append(f"- 需求缺失（补规则可解决）：{b.requirement_gaps}")
    lines.append(f"- 词表缺失（需新增观察维度）：{b.vocab_gaps}")
    lines.append("\n### 缺口清单\n")
    for gap in b.gaps:
        tag = "需求缺失" if gap.kind == "requirement_gap" else "词表缺失"
        example = f" 反例={gap.example_state}" if gap.example_state else ""
        lines.append(f"- [{tag}] {gap.id}（{gap.source}）：{gap.desc}{example}")
    lines.append("")

    lines.append("## 7. threats to validity（显式假设）\n")
    for assumption in report.assumptions:
        lines.append(f"- {assumption}")
    lines.append("")

    return "\n".join(lines)


def write_reports(policy: Policy, out_dir: str) -> tuple[str, str, str]:
    os.makedirs(out_dir, exist_ok=True)
    report = build_report(policy)
    md_path = os.path.join(out_dir, "report.md")
    json_path = os.path.join(out_dir, "report.json")
    smt_path = os.path.join(out_dir, "policy.smt2")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report))
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(report.model_dump_json(indent=2))
    export_smtlib(policy, smt_path)

    return md_path, json_path, smt_path
