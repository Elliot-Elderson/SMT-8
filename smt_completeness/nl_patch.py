import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable

from .analysis.defects import DeadClause, check_defects
from .analysis.redundancy import check_duplicates
from .ir import Policy, RuleKind
from .nl_render import (
    render_dead_line,
    render_duplicate_line,
    render_gap_line,
    render_silent_line,
)


@dataclass(frozen=True)
class PatchStats:
    added: int
    dead_annotated: int
    duplicate_annotated: int
    source_lines: int
    added_lines: int


_CATEGORY_ORDER = {
    "new_deny": 0,
    "new_challenge": 1,
    "dead": 2,
    "duplicate": 3,
}


def original_lines_preserved(source_md: str, patched: str) -> tuple[bool, int, int]:
    source_lines = source_md.splitlines()
    patched_lines = patched.splitlines()
    index = 0
    for line in patched_lines:
        if index < len(source_lines) and line == source_lines[index]:
            index += 1
    ok = index == len(source_lines)
    added_lines = len(patched_lines) - len(source_lines)
    return ok, len(source_lines), added_lines


def apply_nl_patch(
    source_md: str,
    initial: Policy,
    final: Policy,
    *,
    dead_clauses: list[DeadClause] | None = None,
    duplicate_rule_ids: list[str] | None = None,
) -> tuple[str, PatchStats]:
    if dead_clauses is None:
        dead_clauses = check_defects(initial).dead_clauses
    if duplicate_rule_ids is None:
        duplicate_rule_ids = check_duplicates(initial)

    initial_by_id = {rule.id: rule for rule in initial.rules}
    final_by_id = {rule.id: rule for rule in final.rules}
    added_rules = [
        rule for rule_id, rule in final_by_id.items() if rule_id not in initial_by_id
    ]

    lines = source_md.splitlines()
    keep_trailing_newline = source_md.endswith("\n")
    bullet_inserts: dict[int, list[tuple[int, str, str]]] = defaultdict(list)
    completion_lines: dict[str, list[str]] = defaultdict(list)
    silent_lines: list[str] = []

    def attach(anchor: str, category: str, rule_id: str, line: str, kind: RuleKind) -> None:
        index = _find_bullet_index(lines, anchor)
        if index is not None:
            bullet_inserts[index].append((_CATEGORY_ORDER[category], rule_id, line))
            return
        completion_lines[_section_prefix_for_kind(kind)].append(line)

    for rule in added_rules:
        defect = rule.justification.defect if rule.justification is not None else None
        if defect == "silent_permission":
            silent_lines.append(render_silent_line(rule))
            continue
        if defect == "sensitivity_gap":
            category = (
                "new_deny" if rule.kind == RuleKind.MANDATORY_DENY else "new_challenge"
            )
            attach(rule.source_anchor, category, rule.id, render_gap_line(rule), rule.kind)

    completion_lines["## 4."].extend(silent_lines)

    for clause in dead_clauses:
        rule = initial_by_id.get(clause.rule_id)
        rendered = render_dead_line(clause)
        if rule is None:
            completion_lines["## 3."].append(rendered)
            continue
        attach(rule.source_anchor, "dead", clause.rule_id, rendered, rule.kind)

    for rule_id in duplicate_rule_ids:
        rule = initial_by_id.get(rule_id)
        rendered = render_duplicate_line(rule_id)
        if rule is None:
            completion_lines["## 3."].append(rendered)
            continue
        attach(rule.source_anchor, "duplicate", rule_id, rendered, rule.kind)

    for index in sorted(bullet_inserts, reverse=True):
        grouped = sorted(bullet_inserts[index], key=lambda item: (item[0], item[1]))
        lines[index + 1 : index + 1] = [item[2] for item in grouped]

    text = "\n".join(lines)
    if keep_trailing_newline:
        text += "\n"

    for section_prefix, new_lines in completion_lines.items():
        if new_lines:
            text = _insert_under_completion_heading(text, section_prefix, new_lines)

    n_deny = sum(
        1
        for rule in added_rules
        if rule.justification is not None
        and rule.justification.defect == "sensitivity_gap"
        and rule.kind == RuleKind.MANDATORY_DENY
    )
    n_challenge = sum(
        1
        for rule in added_rules
        if rule.justification is not None
        and rule.justification.defect == "sensitivity_gap"
        and rule.kind == RuleKind.MUST_CHALLENGE
    )
    n_explicit = sum(
        1
        for rule in added_rules
        if rule.justification is not None
        and rule.justification.defect == "silent_permission"
    )
    source_line_count = len(source_md.splitlines())
    text = _insert_summary_block(
        text,
        n_deny=n_deny,
        n_challenge=n_challenge,
        n_explicit=n_explicit,
        n_dead=len(dead_clauses),
        n_duplicate=len(duplicate_rule_ids),
        n_source=source_line_count,
    )

    _, source_lines, added_lines = original_lines_preserved(source_md, text)
    return text, PatchStats(
        added=len(added_rules),
        dead_annotated=len(dead_clauses),
        duplicate_annotated=len(duplicate_rule_ids),
        source_lines=source_lines,
        added_lines=added_lines,
    )


def _section_prefix_for_kind(kind: RuleKind) -> str:
    if kind == RuleKind.MUST_CHALLENGE:
        return "## 4."
    if kind == RuleKind.MAY_ALLOW:
        return "## 5."
    return "## 3."


def _find_bullet_index(lines: list[str], source_anchor: str) -> int | None:
    anchor = _strip_section_anchor(source_anchor).strip()
    if not anchor:
        return None
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped.startswith("- ") or stripped.startswith("- 〔"):
            continue
        if anchor in line:
            return index
    return None


def _strip_section_anchor(source_anchor: str) -> str:
    return re.sub(r"^§[^·]+ ·\s*", "", source_anchor)


def _insert_summary_block(
    text: str,
    *,
    n_deny: int,
    n_challenge: int,
    n_explicit: int,
    n_dead: int,
    n_duplicate: int,
    n_source: int,
) -> str:
    block = [
        "> ## 本次补全摘要",
        ">",
        f"> - 新增拒绝 {n_deny} 条：依据敏感度偏序，均附依据条款与反例",
        f"> - 新增判断 {n_challenge} 条：同上，强度为「进一步判断」",
        f"> - 显式化 {n_explicit} 条：原本静默落入默认允许，文档从未表态",
        f"> - 失效条款 {n_dead} 处：写在文档里但当前永不生效，需人工裁决",
        f"> - 重复条款 {n_duplicate} 处：在当前词表下与同类条款重复",
        f"> - 原文 {n_source} 行逐字未改，未删除任何原有条款",
        ">",
        "> 数据见 `report_after.md`「不回归保证」与「回放对照」两节。",
        "",
    ]
    lines = text.splitlines()
    keep_trailing_newline = text.endswith("\n")
    first_h2 = _find_line_index(lines, lambda line: line.startswith("## "))
    if first_h2 is None:
        suffix = "" if text.endswith("\n") else "\n"
        return text + suffix + "\n".join(block) + "\n"
    lines[first_h2:first_h2] = block
    patched = "\n".join(lines)
    return patched + "\n" if keep_trailing_newline else patched


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
