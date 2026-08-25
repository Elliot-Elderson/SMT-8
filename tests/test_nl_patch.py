from smt_completeness.ir import Policy, Provenance, RuleKind
from smt_completeness.nl_patch import apply_nl_patch
from smt_completeness.vocab import Operation, ResourceClass, TargetZone
from tests.policy_fixtures import deny_read_private_context, make_rule


SRC = """# 文档

## 3. 必须拒绝的行为

- 禁止读取 Agent 私有上下文文件

## 4. 必须进一步判断的行为

- 外发普通文件需进一步判断

## 5. 可以保留的正常工作流

- 本地读普通文件
"""


def test_inserts_synthesized_deny_under_section_3():
    initial = Policy(rules=[deny_read_private_context()])
    extra = make_rule(
        "SYN-0-1",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.AGENT_MEMORY],
        source_anchor="补全 · 倒挂对齐",
        provenance=Provenance.SYNTHESIZED,
    )
    final = Policy(rules=initial.rules + [extra])
    text, stats = apply_nl_patch(SRC, initial, final)
    assert stats.added == 1
    assert "Agent 记忆" in text or "agent_memory" in text
    assert "补全 · 倒挂对齐" in text
    assert "## 5." in text
    assert "- 本地读普通文件" in text


def test_no_duplicate_annotation_when_source_anchor_is_annotation():
    initial = Policy(rules=[deny_read_private_context()])
    extra = make_rule(
        "SYN-0-2",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.AGENT_MEMORY],
        source_anchor="补全 · 倒挂对齐",
        provenance=Provenance.SYNTHESIZED,
    )
    final = Policy(rules=initial.rules + [extra])
    text, _ = apply_nl_patch(SRC, initial, final)
    assert "补全 · 倒挂对齐；补全 · 倒挂对齐" not in text
    assert "补全 · 倒挂对齐" in text


def test_deleted_rule_gets_annotation():
    r = deny_read_private_context()
    r = r.model_copy(update={"source_anchor": "§3.1 · 禁止读取 Agent 私有上下文文件"})
    initial = Policy(rules=[r])
    text, stats = apply_nl_patch(SRC, initial, Policy(rules=[]))
    assert stats.removed == 1
    assert "删除后判定函数不变" in text or "已被更严拒绝覆盖" in text


def test_two_deletes_same_anchor_keep_both_ids():
    src = """## 3. 必须拒绝的行为

- 禁止读取或列举第 2.1 节定义的凭据文件和凭据目录。
"""
    r1 = make_rule(
        "R3.1",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
        source_anchor="禁止读取或列举第 2.1 节定义的凭据文件和凭据目录。",
    )
    r2 = make_rule(
        "R3.2",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.LIST],
        resource_class=[ResourceClass.CREDENTIAL],
        source_anchor="禁止读取或列举第 2.1 节定义的凭据文件和凭据目录。",
    )
    text, stats = apply_nl_patch(src, Policy(rules=[r1, r2]), Policy(rules=[]))
    assert stats.removed == 2
    assert "R3.1" in text and "R3.2" in text
    assert text.count("已删除规则") == 2


def test_insert_uses_section_containing_source_anchor():
    initial = Policy(rules=[])
    allow = make_rule(
        "A5.1",
        RuleKind.MAY_ALLOW,
        operation=[Operation.READ],
        resource_class=[ResourceClass.NORMAL_FILE],
        target_zone=[TargetZone.LOCAL],
        source_anchor="本地读普通文件",
    )
    text, stats = apply_nl_patch(SRC, initial, Policy(rules=[allow]))
    assert stats.added == 1
    section_5 = text.split("## 5.")[1]
    assert "A5.1" not in text
    assert "本地读普通文件；补全 · 未表态显式化" in section_5


def test_narrowed_without_initial_overlap_uses_hygiene_generalization_reason():
    initial_rule = make_rule(
        "C4.1",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.SEND, Operation.WRITE],
        resource_class=[ResourceClass.NORMAL_FILE],
    )
    final_rule = initial_rule.model_copy(
        update={
            "condition": initial_rule.condition.model_copy(
                update={"operation": [Operation.SEND]}
            )
        }
    )
    text, stats = apply_nl_patch(SRC, Policy(rules=[initial_rule]), Policy(rules=[final_rule]))
    assert stats.narrowed == 1
    assert "收窄条件（卫生泛化）" in text
    assert "收窄以免与拒绝重叠" not in text
