from smt_completeness.ir import Justification, Policy, Provenance, RuleKind
from smt_completeness.nl_patch import apply_nl_patch, original_lines_preserved
from smt_completeness.nl_render import TAG_EXPLICIT, TAG_NEW_DENY
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


def test_gap_rule_is_inserted_under_evidence_bullet():
    evidence = deny_read_private_context().model_copy(
        update={"source_anchor": "禁止读取 Agent 私有上下文文件"}
    )
    extra = make_rule(
        "SYN-0-1",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.AGENT_MEMORY],
        source_anchor=evidence.source_anchor,
        provenance=Provenance.SYNTHESIZED,
        justification=Justification(
            defect="sensitivity_gap",
            evidence_rule_ids=[evidence.id],
            witness={
                "operation": "read",
                "resource_class": "agent_memory",
                "target_zone": "local",
                "flags": [],
            },
            witness_decision_before=0,
            witness_decision_after=2,
        ),
    )
    text, stats = apply_nl_patch(SRC, Policy(rules=[evidence]), Policy(rules=[evidence, extra]))
    assert stats.added == 1
    assert TAG_NEW_DENY in text
    section_3 = text.split("## 3.")[1].split("## 4.")[0]
    assert TAG_NEW_DENY in section_3
    assert "补全 · 倒挂对齐" not in text
    ok, source_lines, added_lines = original_lines_preserved(SRC, text)
    assert ok is True
    assert source_lines == len(SRC.splitlines())
    assert added_lines >= 1
    for line in SRC.splitlines():
        assert line in text.splitlines()


def test_silent_rule_goes_to_section_4_completion():
    extra = make_rule(
        "SYN-0-2",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.LIST],
        resource_class=[ResourceClass.PRIVATE_DATA],
        target_zone=[TargetZone.LOCAL],
        source_anchor="",
        provenance=Provenance.SYNTHESIZED,
        justification=Justification(
            defect="silent_permission",
            evidence_rule_ids=[],
            witness={
                "operation": "list",
                "resource_class": "private_data",
                "target_zone": "local",
                "flags": [],
            },
            witness_decision_before=0,
            witness_decision_after=1,
        ),
    )
    text, stats = apply_nl_patch(SRC, Policy(rules=[]), Policy(rules=[extra]))
    assert stats.added == 1
    section_4 = text.split("## 4.")[1].split("## 5.")[0]
    assert TAG_EXPLICIT in section_4
    assert "### 补全追加" in section_4


def test_summary_block_before_first_h2():
    extra = make_rule(
        "SYN-0-2",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.LIST],
        resource_class=[ResourceClass.PRIVATE_DATA],
        target_zone=[TargetZone.LOCAL],
        source_anchor="",
        provenance=Provenance.SYNTHESIZED,
        justification=Justification(
            defect="silent_permission",
            evidence_rule_ids=[],
            witness={
                "operation": "list",
                "resource_class": "private_data",
                "target_zone": "local",
                "flags": [],
            },
            witness_decision_before=0,
            witness_decision_after=1,
        ),
    )
    text, _ = apply_nl_patch(SRC, Policy(rules=[]), Policy(rules=[extra]))
    assert text.index("本次补全摘要") < text.index("## 3.")
    assert "未删除任何原有条款" in text


def test_does_not_delete_or_rewrite_source_lines():
    r = deny_read_private_context()
    text, stats = apply_nl_patch(SRC, Policy(rules=[r]), Policy(rules=[r]))
    assert not hasattr(stats, "removed")
    assert "- 禁止读取 Agent 私有上下文文件" in text
    assert "已删除规则" not in text
    assert "删除后判定函数不变" not in text
