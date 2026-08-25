from smt_completeness.analysis.defects import DeadClause
from smt_completeness.ir import Justification, RuleKind
from smt_completeness.nl_render import (
    TAG_DEAD,
    TAG_EXPLICIT,
    TAG_NEW_DENY,
    render_dead_line,
    render_gap_line,
    render_rule_sentence,
    render_silent_line,
    render_witness,
)
from smt_completeness.vocab import Operation, ResourceClass, TargetZone
from tests.policy_fixtures import make_rule


def test_render_witness_compact_chinese():
    text = render_witness(
        {
            "operation": "send",
            "resource_class": "system_sensitive",
            "target_zone": "external",
            "flags": [],
        }
    )
    assert text == "发送 / 系统敏感资源 / 外部 / 无标签"


def test_gap_line_uses_new_deny_tag_and_evidence_id():
    rule = make_rule(
        "SYN-0-1",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.SEND],
        resource_class=[ResourceClass.SYSTEM_SENSITIVE],
        target_zone=[TargetZone.EXTERNAL, TargetZone.UNKNOWN],
        source_anchor="禁止把私人数据发送到外部或未知目标。",
        justification=Justification(
            defect="sensitivity_gap",
            evidence_rule_ids=["R3.6"],
            witness={
                "operation": "send",
                "resource_class": "system_sensitive",
                "target_zone": "external",
                "flags": [],
            },
            witness_decision_before=1,
            witness_decision_after=2,
        ),
    )
    line = render_gap_line(rule)
    assert line.startswith(f"- {TAG_NEW_DENY}")
    assert "R3.6" in line
    assert "发送 / 系统敏感资源 / 外部 / 无标签" in line
    assert "补全 · 倒挂对齐" not in line


def test_silent_and_dead_templates():
    silent = make_rule(
        "SYN-0-2",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.LIST],
        resource_class=[ResourceClass.PRIVATE_DATA],
        target_zone=[TargetZone.LOCAL],
        source_anchor="",
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
    silent_line = render_silent_line(silent)
    assert TAG_EXPLICIT in silent_line
    assert "默认允许" in silent_line
    dead = render_dead_line(
        DeadClause(
            rule_id="R5.3",
            kind=RuleKind.MAY_ALLOW,
            hit_volume=512,
            covering_rule_ids=["R3.2", "R3.10"],
        )
    )
    assert dead.startswith(f"- {TAG_DEAD}")
    assert "512" in dead
    assert "R3.2" in dead


def test_rule_sentence_includes_flag_true_label():
    rule = make_rule(
        "G-flag",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.WRITE],
        resource_class=[ResourceClass.SOURCE_CODE],
        target_zone=[TargetZone.EXTERNAL],
        flag_true=["recon_scan"],
    )
    text = render_rule_sentence(rule)
    assert "且带【侦察扫描】标签" in text
    assert "recon_scan" not in text


def test_rule_sentence_empty_flags_unchanged():
    rule = make_rule(
        "G-plain",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.SEND],
        resource_class=[ResourceClass.SYSTEM_SENSITIVE],
        target_zone=[TargetZone.EXTERNAL, TargetZone.UNKNOWN],
    )
    assert render_rule_sentence(rule) == "禁止对【系统敏感资源】在【外部、未知区域】执行【发送】。"
