from smt_completeness.analysis.defects import DeadClause
from smt_completeness.ir import Rule, RuleKind

TAG_NEW_DENY = "〔新增拒绝〕"
TAG_NEW_CHALLENGE = "〔新增判断〕"
TAG_DEAD = "〔失效条款〕"
TAG_EXPLICIT = "〔显式化〕"
TAG_DUPLICATE = "〔重复条款〕"

DECISION_LABELS = {
    0: "允许",
    1: "进一步判断",
    2: "拒绝",
}

FLAG_LABELS = {
    "weakens_control": "弱化控制",
    "persistence": "持久化",
    "privilege_esc": "提权",
    "supply_chain_exec": "供应链执行",
    "destructive": "破坏性",
    "recon_scan": "侦察扫描",
    "taint_credential": "凭据污染",
    "taint_private_data": "私人数据污染",
    "taint_session_data": "会话数据污染",
}

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


def render_witness(state: dict) -> str:
    operation = _OPERATION_LABELS.get(
        state.get("operation", ""), state.get("operation", "")
    )
    resource = _RESOURCE_LABELS.get(
        state.get("resource_class", ""), state.get("resource_class", "")
    )
    target = _TARGET_LABELS.get(state.get("target_zone", ""), state.get("target_zone", ""))
    flags = state.get("flags", [])
    if flags:
        flag_text = "、".join(FLAG_LABELS.get(flag, flag) for flag in flags)
    else:
        flag_text = "无标签"
    return f"{operation} / {resource} / {target} / {flag_text}"


def render_rule_sentence(rule: Rule) -> str:
    resource = _format_dimension(rule.condition.resource_class, _RESOURCE_LABELS)
    target = _format_dimension(rule.condition.target_zone, _TARGET_LABELS)
    operation = _format_dimension(rule.condition.operation, _OPERATION_LABELS)
    flags = _format_flag_clause(rule.condition.flag_true, rule.condition.flag_false)

    if rule.kind == RuleKind.MANDATORY_DENY:
        return f"禁止对【{resource}】在【{target}】执行【{operation}】{flags}。"
    if rule.kind == RuleKind.MUST_CHALLENGE:
        return f"对【{resource}】在【{target}】执行【{operation}】{flags}时必须进一步判断。"
    return f"对【{resource}】在【{target}】执行【{operation}】{flags}。"


def render_gap_line(rule: Rule) -> str:
    sentence = render_rule_sentence(rule)
    tag = TAG_NEW_DENY if rule.kind == RuleKind.MANDATORY_DENY else TAG_NEW_CHALLENGE
    justification = rule.justification
    assert justification is not None
    evidence_id = justification.evidence_rule_ids[0] if justification.evidence_rule_ids else ""
    witness = render_witness(justification.witness)
    before = DECISION_LABELS[justification.witness_decision_before]
    body = (
        f"{tag}{sentence}依据：上句（{evidence_id}）已约束更低或同级敏感资源，"
        f"本资源敏感度不低于该依据。反例：{witness}，原判定为{before}。"
    )
    return f"- {body}"


def render_silent_line(rule: Rule) -> str:
    sentence = render_rule_sentence(rule)
    justification = rule.justification
    assert justification is not None
    witness = render_witness(justification.witness)
    body = f"{TAG_EXPLICIT}{sentence}反例：{witness}，原本静默落入默认允许，文档从未表态。"
    return f"- {body}"


def render_dead_line(clause: DeadClause) -> str:
    ids = "、".join(clause.covering_rule_ids)
    body = (
        f"{TAG_DEAD}上句当前永不生效：命中 {clause.hit_volume} 个状态全部被 {ids} 覆盖。"
        f"需人工裁决是放宽拒绝条款还是删除本承诺。"
    )
    return f"- {body}"


def render_duplicate_line(rule_id: str) -> str:
    body = (
        f"{TAG_DUPLICATE}上句对应的规则 {rule_id} 在当前词表下已被同类条款完全包含。"
        f"词表更细时两者可能不同，故不删除。"
    )
    return f"- {body}"


def _format_flag_clause(flag_true: list[str], flag_false: list[str]) -> str:
    parts: list[str] = []
    if flag_true:
        labels = "、".join(FLAG_LABELS.get(flag, flag) for flag in flag_true)
        parts.append(f"且带【{labels}】标签")
    if flag_false:
        labels = "、".join(FLAG_LABELS.get(flag, flag) for flag in flag_false)
        parts.append(f"且不含【{labels}】标签")
    return "".join(parts)


def _format_dimension(values: list[object], labels: dict[str, str]) -> str:
    if not values:
        return "任意"
    return "、".join(labels.get(_enum_value(value), _enum_value(value)) for value in values)


def _enum_value(value: object) -> str:
    return str(getattr(value, "value", value))
