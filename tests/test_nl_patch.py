from smt_completeness.ir import Policy, Provenance, RuleKind
from smt_completeness.nl_patch import apply_nl_patch
from smt_completeness.vocab import Operation, ResourceClass
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


def test_deleted_rule_gets_annotation():
    r = deny_read_private_context()
    r = r.model_copy(update={"source_anchor": "§3.1 · 禁止读取 Agent 私有上下文文件"})
    initial = Policy(rules=[r])
    text, stats = apply_nl_patch(SRC, initial, Policy(rules=[]))
    assert stats.removed == 1
    assert "删除后判定函数不变" in text or "已被更严拒绝覆盖" in text
