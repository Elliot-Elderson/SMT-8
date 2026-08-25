import os

from pydantic import BaseModel

from .analysis.clauses import ClauseCoverageReport, check_clause_coverage
from .analysis.consistency import ConflictReport, check_consistency, state_to_dict
from .analysis.coverage import CoverageReport, check_coverage
from .analysis.defects import DefectReport, check_defects
from .analysis.evidence import EvidenceReport, enumerate_justified_gaps
from .analysis.monotonicity import MonotonicityReport, check_monotonicity
from .analysis.redundancy import RedundancyReport, check_duplicates, check_redundancy
from .analysis.tightening import TighteningReport, check_tightening
from .compiler import decide_py, export_smtlib, find_witness
from .completion import CompletionResult
from .extractor import ExtractQa, SelfCheckReport, self_check
from .ir import Policy, Rule, RuleKind
from .vocab import ALL_FLAGS

ASSUMPTIONS = [
    "A1 不引入 tool 维度——文档所有规则按操作与风险特征表述。",
    "A2 资源分类器完美（布尔抽象）——路径变形绕过原型阶段不可见。",
    "A3 MustAllow 推导正确（§5 减 §3、§4）——决定可收紧性结论强度上限。",
    "A4 H1 只覆盖规则级收紧——H1 tight ≠ 绝对 tight。",
    "A5 敏感度偏序从章节顺序推导——需人工复核该算子每个输出。",
    "A7 需求集不含管理性语义（委派/角色授予）——否则落入 HRU 不可判定区。",
    "A8 本期不使用外部威胁宇宙，内部指标不声称外部攻击覆盖。",
    "A9 敏感度偏序从章节顺序推导，因此「有依据缺口」的依据只到「文档禁止了更低敏感的同类操作」这一层。它不能证明高敏感侧确实应当禁止，只能证明当前文档在偏序上不自洽。",
    "A10 `mandatory_deny` 覆盖 `must_challenge` 是文档 §6.3 规定的有意分层，不是矛盾。只有有效体积归零才算缺陷。这条假设一旦不成立（例如某文档确实要求 §4 优先），整个优先级重叠指标的解读要反过来。",
]


class ReplayRow(BaseModel):
    state: dict
    decision_before: int
    decision_after: int
    related_rule_id: str | None = None


class FullReport(BaseModel):
    self_check: SelfCheckReport
    consistency: ConflictReport
    redundancy: RedundancyReport
    coverage: CoverageReport
    tightening: TighteningReport
    monotonicity: MonotonicityReport
    assumptions: list[str]
    defects: DefectReport
    evidence: EvidenceReport
    clause_coverage: ClauseCoverageReport | None = None
    duplicate_rule_ids: list[str]
    replay: list[ReplayRow]


def _match_constraint(rule: Rule):
    def constraint(env):
        return env.match_expr(rule)

    return constraint


def _build_replay(policy: Policy, initial_policy: Policy | None) -> list[ReplayRow]:
    rows: list[ReplayRow] = []
    for rule in policy.rules:
        if rule.justification is None:
            continue
        justification = rule.justification
        rows.append(
            ReplayRow(
                state=justification.witness,
                decision_before=justification.witness_decision_before,
                decision_after=justification.witness_decision_after,
                related_rule_id=rule.id,
            )
        )
    if initial_policy is None:
        return rows
    for rule in policy.rules:
        if rule.kind != RuleKind.MAY_ALLOW:
            continue
        witness = find_witness(policy, _match_constraint(rule))
        if witness is None:
            continue
        rows.append(
            ReplayRow(
                state=state_to_dict(witness),
                decision_before=int(decide_py(witness, initial_policy)),
                decision_after=int(decide_py(witness, policy)),
                related_rule_id=rule.id,
            )
        )
    return rows


def build_report(
    policy: Policy,
    *,
    source_md: str | None = None,
    initial_policy: Policy | None = None,
) -> FullReport:
    clause_coverage = None
    if source_md:
        clause_coverage = check_clause_coverage(policy, source_md)
    return FullReport(
        self_check=self_check(policy),
        consistency=check_consistency(policy),
        redundancy=check_redundancy(policy),
        coverage=check_coverage(policy),
        tightening=check_tightening(policy),
        monotonicity=check_monotonicity(policy),
        assumptions=ASSUMPTIONS,
        defects=check_defects(policy),
        evidence=enumerate_justified_gaps(policy),
        clause_coverage=clause_coverage,
        duplicate_rule_ids=check_duplicates(policy),
        replay=_build_replay(policy, initial_policy),
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
        "skipped": sum(len(round.skipped) for round in completion.rounds),
    }


def _append_defect_section(
    lines: list[str],
    report: FullReport,
    compare: FullReport | None,
    completion: CompletionResult | None,
) -> None:
    lines.append("## 缺陷清单\n")
    if compare is not None:
        lines.append("| 指标 | before | after |")
        lines.append("| --- | ---: | ---: |")
        lines.append(
            _compare_row(
                "有依据缺口",
                compare.evidence.justified_gap_count,
                report.evidence.justified_gap_count,
            )
        )
        lines.append(
            _compare_row(
                "静默允许",
                compare.defects.silent_permission_volume,
                report.defects.silent_permission_volume,
            )
        )
        lines.append("")
    else:
        lines.append(f"- 有依据缺口：{report.evidence.justified_gap_count}")
        lines.append(f"- 静默允许：{report.defects.silent_permission_volume}")
        lines.append("")

    if report.evidence.gaps:
        lines.append("### 有依据缺口反例\n")
        for gap in report.evidence.gaps[:8]:
            lines.append(
                f"- {gap.witness} 依据={gap.evidence_rule_id} "
                f"before={gap.witness_decision_before} after={gap.witness_decision_after}"
            )
        lines.append("")
    if report.defects.silent_permission_states:
        lines.append("### 静默允许反例\n")
        for state in report.defects.silent_permission_states[:8]:
            lines.append(f"- {state}")
        lines.append("")

    if completion is not None and completion.remaining_reasons:
        lines.append("### 未归零原因\n")
        for reason in completion.remaining_reasons:
            lines.append(f"- {reason}")
        lines.append("")


def _append_detection_section(lines: list[str], report: FullReport) -> None:
    lines.append("## 检出清单\n")
    if not report.defects.dead_clauses:
        lines.append("- 无死条款")
        lines.append("")
        return
    for clause in report.defects.dead_clauses:
        covering = clause.covering_rule_ids or "无"
        lines.append(
            f"- {clause.rule_id} kind={clause.kind.value} "
            f"命中体积={clause.hit_volume} 覆盖规则={covering}"
        )
    lines.append("")


def _append_non_regression_placeholder(
    lines: list[str], compare: FullReport | None
) -> None:
    lines.append("## 不回归保证\n")
    if compare is None:
        lines.append("见补全后报告")
    else:
        lines.append("（占位，由 CLI 在补全后逐条打勾）")
    lines.append("")


def _append_replay_section(lines: list[str], report: FullReport) -> None:
    lines.append("## 回放对照\n")
    lines.append("| 状态 | 改前 | 改后 | 关联规则 |")
    lines.append("| --- | --- | --- | --- |")
    if not report.replay:
        lines.append("| （无样本） |  |  |  |")
    else:
        for row in report.replay:
            related = row.related_rule_id or ""
            lines.append(
                f"| {row.state} | {row.decision_before} | {row.decision_after} | {related} |"
            )
    lines.append("")


def _append_observation_section(lines: list[str], report: FullReport) -> None:
    c = report.coverage
    lines.append("## 观察指标\n")
    lines.append(
        f"- 优先级重叠体积：{report.defects.precedence_overlap_volume}"
    )
    for ratio in report.defects.overlap_ratios:
        lines.append(
            f"  - {ratio.rule_id}（{ratio.kind.value}）"
            f"有效={ratio.effective_volume} / 命中={ratio.hit_volume}"
        )
    lines.append(
        f"- 兜底依赖体积：{_format_metric(c.v_unspecified_challenge, c.v_unspecified_challenge_ratio)}"
    )
    if c.unspecified_cubes:
        lines.append("  - 兜底依赖 Top-8 立方体：")
        for cube in c.unspecified_cubes[:8]:
            lines.append(f"    - {_format_cube(cube)}")
    lines.append(f"- 未表态体积：{_format_metric(c.v_unspecified, c.v_unspecified_ratio)}")
    lines.append(f"- V_explicit（显式覆盖，策略表达力）：{c.v_explicit}（{c.v_explicit_ratio:.2%}）")
    lines.append(f"- V_unspecified（未显式表态）：{c.v_unspecified}（{c.v_unspecified_ratio:.2%}）")
    lines.append(
        f"- V_unspecified_allow（未表态且默认 Allow）：{c.v_unspecified_allow}（{c.v_unspecified_allow_ratio:.2%}）"
    )
    lines.append(
        f"- V_unspecified_challenge（未表态且默认 Challenge）："
        f"{c.v_unspecified_challenge}（{c.v_unspecified_challenge_ratio:.2%}）"
    )
    if report.clause_coverage is not None:
        cc = report.clause_coverage
        lines.append(
            f"- 条款覆盖：判定子弹 {cc.total_bullets}，已锚定 {cc.anchored_count}，"
            f"未锚定 {len(cc.unanchored)}"
        )
        for bullet in cc.unanchored[:8]:
            lines.append(f"  - [{bullet.reason}] {bullet.chapter}: {bullet.text}")
    lines.append(f"- duplicate_rule_ids：{report.duplicate_rule_ids or '无'}")
    lines.append(f"- 倒挂数：{report.monotonicity.inversion_count}")
    lines.append(f"- 同级不对称：{report.monotonicity.equal_rank_asymmetry_count}")
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
    lines.append(f"- 是否 H1 tight（相对规则级收紧空间）：{report.tightening.is_h1_tight}")
    lines.append(f"- 可收紧规则：{report.tightening.tightenable_rule_ids or '无'}")
    lines.append("")


def _append_compare_table(
    lines: list[str],
    report: FullReport,
    compare: FullReport,
    completion: CompletionResult | None,
) -> None:
    before = compare
    after = report
    lines.append("## 补全前后对照\n")
    lines.append("| 指标 | before | after |")
    lines.append("| --- | ---: | ---: |")
    lines.append(
        _compare_row(
            "有依据缺口",
            before.evidence.justified_gap_count,
            after.evidence.justified_gap_count,
        )
    )
    lines.append(
        _compare_row(
            "静默允许",
            before.defects.silent_permission_volume,
            after.defects.silent_permission_volume,
        )
    )
    lines.append(
        _compare_row(
            "优先级重叠（仅观察）",
            before.defects.precedence_overlap_volume,
            after.defects.precedence_overlap_volume,
        )
    )
    lines.append(
        _compare_row(
            "兜底依赖体积（仅观察）",
            before.coverage.v_unspecified_challenge,
            after.coverage.v_unspecified_challenge,
        )
    )
    lines.append(
        _compare_row(
            "V_unspecified（仅观察）",
            before.coverage.v_unspecified,
            after.coverage.v_unspecified,
        )
    )
    lines.append(
        _compare_row(
            "V_explicit（仅观察）",
            before.coverage.v_explicit,
            after.coverage.v_explicit,
        )
    )
    lines.append(
        _compare_row(
            "倒挂数（仅观察）",
            before.monotonicity.inversion_count,
            after.monotonicity.inversion_count,
        )
    )
    lines.append(
        _compare_row(
            "同级不对称（仅观察）",
            before.monotonicity.equal_rank_asymmetry_count,
            after.monotonicity.equal_rank_asymmetry_count,
        )
    )
    lines.append(
        _compare_row(
            "H1 tight（仅观察）",
            before.tightening.is_h1_tight,
            after.tightening.is_h1_tight,
        )
    )
    lines.append(
        _compare_row(
            "规则数",
            before.self_check.total_rules,
            after.self_check.total_rules,
        )
    )
    lines.append("")
    if completion is not None:
        totals = _completion_totals(completion)
        lines.append("### 补全摘要\n")
        lines.append(f"- 轮次：{totals['rounds']}")
        lines.append(f"- 收敛：{totals['converged']}")
        lines.append(f"- 新增规则：{totals['added']}")
        lines.append(f"- 跳过：{totals['skipped']}")
        lines.append("")


def render_markdown(
    report: FullReport,
    *,
    label: str,
    compare: FullReport | None = None,
    completion: CompletionResult | None = None,
    qa: ExtractQa | None = None,
) -> str:
    lines: list[str] = []

    lines.append(f"# Agent 访问控制需求完备性评测报告（{label}）\n")
    lines.append("## 概览\n")
    lines.append(f"- 规则总数：{report.self_check.total_rules}")
    lines.append(
        f"- 自动自检：{'通过' if report.self_check.ok else '未通过'}"
        f"（id 唯一={report.self_check.id_unique}，"
        f"恒假规则={report.self_check.vacuous_rule_ids}）"
    )
    lines.append("")

    _append_defect_section(lines, report, compare, completion)
    _append_detection_section(lines, report)
    _append_non_regression_placeholder(lines, compare)
    _append_replay_section(lines, report)
    _append_observation_section(lines, report)

    if qa is not None:
        lines.append("## 抽取质量")
        lines.append(f"- extraction_mode: {qa.extraction_mode}")
        lines.append(f"- kind_counts: {qa.kind_counts}")
        lines.append(f"- warnings: {qa.warnings}")
        lines.append("")

    if compare is not None:
        _append_compare_table(lines, report, compare, completion)

    lines.append("## 假设\n")
    for assumption in report.assumptions:
        lines.append(f"- {assumption}")
    lines.append("")

    return "\n".join(lines)


def write_policy_reports(
    policy: Policy,
    out_dir: str,
    stem: str,
    report: "FullReport | None" = None,
    qa: ExtractQa | None = None,
) -> tuple[str, str, str]:
    os.makedirs(out_dir, exist_ok=True)
    used_report = report if report is not None else build_report(policy)
    md_path = os.path.join(out_dir, f"{stem}.md")
    json_path = os.path.join(out_dir, f"{stem}.json")
    smt_path = os.path.join(out_dir, f"policy_{stem}.smt2")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(used_report, label=stem, qa=qa))
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(used_report.model_dump_json(indent=2))
    export_smtlib(policy, smt_path)

    return md_path, json_path, smt_path


def write_reports(policy: Policy, out_dir: str) -> tuple[str, str, str]:
    return write_policy_reports(policy, out_dir, "report")
