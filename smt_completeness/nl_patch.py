import re
from dataclasses import dataclass
from typing import Callable

from .ir import Policy, Rule, RuleKind


@dataclass(frozen=True)
class PatchStats:
    added: int
    removed: int
    narrowed: int


_OPERATION_LABELS = {
    "read": "读取",
    "write": "写入",
    "send": "发送",
    "execute": "执行",
    "delete": "删除",
    "list": "列出",
}

_RESOURCE_LABELS = {
    "credential": "凭据",
    "system_sensitive": "系统敏感资源",
    "agent_private_context": "Agent 私有上下文",
    "agent_memory": "Agent 记忆",
    "private_data": "私人数据",
    "config": "配置",
    "source_code": "源代码",
    "normal_file": "普通文件",
    "external_service": "外部服务",
    "unknown": "未知资源",
}

_TARGET_LABELS = {
    "local": "本地",
    "internal": "内部",
    "external": "外部",
    "unknown": "未知区域",
}

_ANNOTATIONS = (
    "已被更严拒绝覆盖",
    "删除后判定函数不变",
    "收窄以免与拒绝重叠",
    "补全 · 倒挂对齐",
    "补全 · 未表态显式化",
)


def apply_nl_patch(source_md: str, initial: Policy, final: Policy) -> tuple[str, PatchStats]:
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
        text = _insert_rule_line(text, rule, _annotation_for_source(rule.source_anchor))

    for rule in narrowed:
        text = _insert_rule_line(text, rule, "收窄以免与拒绝重叠")

    return text, PatchStats(added=len(added), removed=len(removed), narrowed=len(narrowed))


def render_rule_sentence(rule: Rule) -> str:
    resource = _format_dimension(rule.condition.resource_class, _RESOURCE_LABELS)
    target = _format_dimension(rule.condition.target_zone, _TARGET_LABELS)
    operation = _format_dimension(rule.condition.operation, _OPERATION_LABELS)

    if rule.kind == RuleKind.MANDATORY_DENY:
        return f"禁止对【{resource}】在【{target}】执行【{operation}】。"
    if rule.kind == RuleKind.MUST_CHALLENGE:
        return f"对【{resource}】在【{target}】执行【{operation}】时必须进一步判断。"
    return f"对【{resource}】在【{target}】执行【{operation}】。"


def _format_dimension(values: list[object], labels: dict[str, str]) -> str:
    if not values:
        return "任意"
    return "、".join(labels.get(_enum_value(value), _enum_value(value)) for value in values)


def _enum_value(value: object) -> str:
    return str(getattr(value, "value", value))


def _annotation_for_source(source_anchor: str) -> str:
    return source_anchor if source_anchor in _ANNOTATIONS else "补全 · 未表态显式化"


def _insert_rule_line(text: str, rule: Rule, annotation: str) -> str:
    section_prefix = _section_prefix_for(rule.kind)
    sentence = render_rule_sentence(rule)
    line = f"- {sentence}（{rule.source_anchor}；{annotation}）"
    return _insert_under_completion_heading(text, section_prefix, [line])


def _section_prefix_for(kind: RuleKind) -> str:
    if kind == RuleKind.MUST_CHALLENGE:
        return "## 4."
    return "## 3."


def _annotate_removed_rule(text: str, rule: Rule) -> str:
    anchor = _strip_section_anchor(rule.source_anchor)
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.lstrip().startswith("- ") and anchor and anchor in line:
            newline = "\n" if line.endswith("\n") else ""
            lines[index] = (
                f"- *已删除规则 {rule.id}：{anchor}（删除后判定函数不变）*{newline}"
            )
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
    heading = (
        "## 4. 必须进一步判断的行为"
        if section_prefix == "## 4."
        else "## 3. 必须拒绝的行为"
    )
    suffix = "" if text.endswith("\n") else "\n"
    return f"{text}{suffix}\n{heading}\n\n### 补全追加\n\n" + "\n".join(new_lines) + "\n"


def _find_line_index(lines: list[str], predicate: Callable[[str], bool]) -> int | None:
    for index, line in enumerate(lines):
        if predicate(line):
            return index
    return None
