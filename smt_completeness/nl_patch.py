import re
from dataclasses import dataclass
from typing import Callable

from .analysis.consistency import check_consistency
from .ir import Policy, Rule, RuleKind
from .nl_render import render_rule_sentence


@dataclass(frozen=True)
class PatchStats:
    added: int
    removed: int
    narrowed: int


_ANNOTATIONS = (
    "已被更严拒绝覆盖",
    "删除后判定函数不变",
    "收窄以免与拒绝重叠",
    "补全 · 倒挂对齐",
    "补全 · 未表态显式化",
)


def apply_nl_patch(
    source_md: str,
    initial: Policy,
    final: Policy,
    narrowed_reasons: dict[str, str] | None = None,
) -> tuple[str, PatchStats]:
    initial_by_id = {rule.id: rule for rule in initial.rules}
    final_by_id = {rule.id: rule for rule in final.rules}

    added = [rule for rule_id, rule in final_by_id.items() if rule_id not in initial_by_id]
    removed = [rule for rule_id, rule in initial_by_id.items() if rule_id not in final_by_id]
    narrowed = [
        final_by_id[rule_id]
        for rule_id, initial_rule in initial_by_id.items()
        if rule_id in final_by_id
        and initial_rule.condition.model_dump() != final_by_id[rule_id].condition.model_dump()
    ]

    text = source_md
    for rule in removed:
        text = _annotate_removed_rule(text, rule)

    for rule in added:
        text = _insert_rule_line(
            text,
            rule,
            _annotation_for_source(rule.source_anchor),
            source_md=source_md,
        )

    initial_has_overlap = check_consistency(initial).overlap_count > 0 if narrowed else False
    for rule in narrowed:
        reason = (
            narrowed_reasons.get(rule.id)
            if narrowed_reasons is not None and rule.id in narrowed_reasons
            else (
                "收窄以免与拒绝重叠"
                if initial_has_overlap
                else "收窄条件（卫生泛化）"
            )
        )
        text = _insert_rule_line(text, rule, reason, source_md=source_md)

    return text, PatchStats(added=len(added), removed=len(removed), narrowed=len(narrowed))


def _annotation_for_source(source_anchor: str) -> str:
    return source_anchor if source_anchor in _ANNOTATIONS else "补全 · 未表态显式化"


def _insert_rule_line(
    text: str,
    rule: Rule,
    annotation: str,
    *,
    source_md: str | None = None,
) -> str:
    section_prefix = _section_prefix_for(rule.kind, source_md, rule.source_anchor)
    sentence = render_rule_sentence(rule)
    anchor = rule.source_anchor
    if anchor in _ANNOTATIONS:
        line = f"- {sentence}（{anchor}）"
    else:
        line = f"- {sentence}（{anchor}；{annotation}）"
    return _insert_under_completion_heading(text, section_prefix, [line])


def _section_prefix_for(
    kind: RuleKind,
    source_md: str | None = None,
    anchor: str | None = None,
) -> str:
    if source_md and anchor:
        anchor_text = _strip_section_anchor(anchor)
        current_prefix: str | None = None
        for line in source_md.splitlines():
            if line.startswith(("## 3.", "## 4.", "## 5.")):
                current_prefix = line[:5]
            if current_prefix and anchor_text and anchor_text in line:
                return current_prefix

    if kind == RuleKind.MUST_CHALLENGE:
        return "## 4."
    return "## 3."


def _annotate_removed_rule(text: str, rule: Rule) -> str:
    anchor = _strip_section_anchor(rule.source_anchor)
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.lstrip().startswith("- ") and anchor and anchor in line:
            if line.endswith("\n"):
                annotation_line = (
                    f"- *已删除规则 {rule.id}：{anchor}（删除后判定函数不变）*\n"
                )
            else:
                lines[index] = f"{line}\n"
                annotation_line = (
                    f"- *已删除规则 {rule.id}：{anchor}（删除后判定函数不变）*"
                )
            lines[index + 1 : index + 1] = [annotation_line]
            return "".join(lines)

    fallback = anchor or rule.source_anchor
    line = f"- 已删除规则 {rule.id}：{fallback}（删除后判定函数不变）"
    return _insert_under_completion_heading(text, _section_prefix_for(rule.kind), [line])


def _strip_section_anchor(source_anchor: str) -> str:
    return re.sub(r"^§[^·]+ ·\s*", "", source_anchor)


def _insert_under_completion_heading(text: str, section_prefix: str, new_lines: list[str]) -> str:
    lines = text.splitlines()
    keep_trailing_newline = text.endswith("\n")
    section_start = _find_line_index(lines, lambda line: line.startswith(section_prefix))
    if section_start is None:
        return _append_section(text, section_prefix, new_lines)

    section_end = _find_line_index(
        lines[section_start + 1 :], lambda line: line.startswith("## ")
    )
    if section_end is None:
        section_end = len(lines)
    else:
        section_end += section_start + 1

    completion_heading = _find_line_index(
        lines[section_start + 1 : section_end],
        lambda line: line.strip() == "### 补全追加",
    )
    if completion_heading is None:
        insertion = ["", "### 补全追加", "", *new_lines]
        lines[section_end:section_end] = insertion
    else:
        insertion_at = section_start + 1 + completion_heading + 1
        while insertion_at < section_end and lines[insertion_at] == "":
            insertion_at += 1
        lines[insertion_at:insertion_at] = new_lines

    patched = "\n".join(lines)
    return patched + "\n" if keep_trailing_newline else patched


def _append_section(text: str, section_prefix: str, new_lines: list[str]) -> str:
    headings = {
        "## 3.": "## 3. 必须拒绝的行为",
        "## 4.": "## 4. 必须进一步判断的行为",
        "## 5.": "## 5. 可以保留的正常工作流",
    }
    heading = headings.get(section_prefix, "## 3. 必须拒绝的行为")
    suffix = "" if text.endswith("\n") else "\n"
    return f"{text}{suffix}\n{heading}\n\n### 补全追加\n\n" + "\n".join(new_lines) + "\n"


def _find_line_index(lines: list[str], predicate: Callable[[str], bool]) -> int | None:
    for index, line in enumerate(lines):
        if predicate(line):
            return index
    return None
