import re

from .ir import DECISION_KINDS, Policy, Rule, RuleKind

MIN_ANCHOR_LEN = 8
W_NO_DENY_BUT_PROHIBIT = "W_NO_DENY_BUT_PROHIBIT"
W_EXPLICIT_FULL = "W_EXPLICIT_FULL"
W_HIGH_C4 = "W_HIGH_C4"


def split_decision_chapters(source_md: str) -> dict[str, str] | None:
    """能匹配二级标题 ## 3. / ## 4. / ## 5. 则返回 {'3': 正文, '4': ..., '5': ...}（含标题行到下一 ## 之前）；否则 None。"""
    matches = list(
        re.finditer(r"(?m)^##\s+([345])\.\s.*(?:(?:\n(?!##\s+).*)*)", source_md)
    )
    chapters = {match.group(1): match.group(0).rstrip() for match in matches}
    if set(chapters) != {"3", "4", "5"}:
        return None
    return {key: chapters[key] for key in ("3", "4", "5")}


def renumber_rules(rules: list[Rule], prefix: str) -> list[Rule]:
    """prefix 为 'R3'/'R4'/'R5'/'R'，id 改为 f'{prefix}.{n}' n from 1。"""
    return [
        rule.model_copy(update={"id": f"{prefix}.{index}"})
        for index, rule in enumerate(rules, start=1)
    ]


def infer_kind_from_cues(text: str) -> RuleKind | None:
    """优先级：禁止/不得 → DENY；进一步判断/裁决 → CHALLENGE；可以允许或（允许且非不允许/禁止）→ ALLOW。"""
    normalized = text.casefold()
    deny_text = normalized.replace("不禁止", "")
    if "禁止" in deny_text or "不得" in normalized:
        return RuleKind.MANDATORY_DENY
    if "进一步判断" in normalized or "裁决" in normalized:
        return RuleKind.MUST_CHALLENGE
    if "可以允许" in normalized:
        return RuleKind.MAY_ALLOW
    if (
        "允许" in normalized
        and "不允许" not in normalized
        and "禁止" not in deny_text
    ):
        return RuleKind.MAY_ALLOW
    return None


def anchor_is_heading_only(source_md: str, anchor: str) -> bool:
    """子串只出现在 ##/### 行、从未出现在以 '- ' 开头的列表行。"""
    stripped_anchor = anchor.strip()
    if not stripped_anchor:
        return False

    seen_in_heading = False
    for line in source_md.splitlines():
        if stripped_anchor not in line:
            continue
        stripped_line = line.strip()
        if stripped_line.startswith("- "):
            return False
        if stripped_line.startswith("## ") or stripped_line.startswith("### "):
            seen_in_heading = True
        else:
            return False
    return seen_in_heading


def validate_anchor(source_md: str, anchor: str) -> None:
    """strip 后必须是原文子串、len>=8、不得 heading-only；否则 ValueError。"""
    stripped_anchor = anchor.strip()
    if len(stripped_anchor) < MIN_ANCHOR_LEN:
        raise ValueError(f"source_anchor 过短，至少 {MIN_ANCHOR_LEN} 字符: {anchor!r}")
    if stripped_anchor not in source_md:
        raise ValueError(f"source_anchor 不是源文档原文子串: {anchor!r}")
    if anchor_is_heading_only(source_md, stripped_anchor):
        raise ValueError(f"source_anchor 只出现在标题行，不是规则原文: {anchor!r}")


def _containing_bullet(source_md: str, anchor: str) -> str | None:
    for line in source_md.splitlines():
        stripped_line = line.strip()
        if stripped_line.startswith("- ") and anchor in line:
            return stripped_line
    return None


def validate_rule_kind(
    rule: Rule, source_md: str, chapter_default: RuleKind | None
) -> None:
    """
    若锚点落在某条 '- ' 子弹内，线索看整颗子弹；否则看锚点字符串。
    线索 kind 与 rule.kind 不一致 → ValueError。
    无线索：chapter_default 非空则要求 rule.kind==default；flat（default is None）则 ValueError。
    """
    if rule.kind not in DECISION_KINDS:
        return

    anchor = rule.source_anchor.strip()
    cue_text = _containing_bullet(source_md, anchor) or anchor
    inferred = infer_kind_from_cues(cue_text)
    if inferred is not None:
        if inferred != rule.kind:
            raise ValueError(
                f"规则 {rule.id} kind={rule.kind.value!r} 与锚点线索 {inferred.value!r} 不一致"
            )
        return

    if chapter_default is None:
        raise ValueError(f"规则 {rule.id} 的锚点缺少可推断 kind 的句子线索")
    if rule.kind != chapter_default:
        raise ValueError(
            f"规则 {rule.id} kind={rule.kind.value!r} 与章节默认 {chapter_default.value!r} 不一致"
        )


def validate_extracted_policy(
    policy: Policy, source_md: str, chapter_default: RuleKind | None
) -> None:
    """对每个判定 kind 规则跑 validate_anchor + validate_rule_kind。"""
    for rule in policy.rules:
        if rule.kind not in DECISION_KINDS:
            continue
        validate_anchor(source_md, rule.source_anchor)
        validate_rule_kind(rule, source_md, chapter_default)


def collect_quality_warnings(policy: Policy, source_md: str, report) -> list[str]:
    """
    原文 count(禁止)+count(不得) >= 5 且 mandatory_deny==0 → W_NO_DENY_BUT_PROHIBIT
    v_explicit==122880 or v_unspecified==0 → W_EXPLICIT_FULL
    判定规则数>=8 且 C4 冗余占比>=0.8 → W_HIGH_C4
    """
    warnings: list[str] = []
    decision_rules = [rule for rule in policy.rules if rule.kind in DECISION_KINDS]
    deny_count = sum(1 for rule in policy.rules if rule.kind == RuleKind.MANDATORY_DENY)

    if source_md.count("禁止") + source_md.count("不得") >= 5 and deny_count == 0:
        warnings.append(W_NO_DENY_BUT_PROHIBIT)

    if report.coverage.v_explicit == 122880 or report.coverage.v_unspecified == 0:
        warnings.append(W_EXPLICIT_FULL)

    decision_rule_ids = {rule.id for rule in decision_rules}
    redundant_decision_count = sum(
        1
        for rule_id in report.redundancy.redundant_rule_ids
        if rule_id in decision_rule_ids
    )
    if (
        len(decision_rules) >= 8
        and redundant_decision_count / len(decision_rules) >= 0.8
    ):
        warnings.append(W_HIGH_C4)

    return warnings
