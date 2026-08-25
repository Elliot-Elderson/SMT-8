import pytest

from smt_completeness.extract_validate import (
    W_NO_DENY_BUT_PROHIBIT,
    anchor_is_heading_only,
    collect_quality_warnings,
    infer_kind_from_cues,
    validate_anchor,
    validate_extracted_policy,
    validate_rule_kind,
)
from smt_completeness.ir import Condition, Policy, Priority, Rule, RuleKind
from smt_completeness.report import build_report
from smt_completeness.vocab import Decision, Operation, ResourceClass
from tests.policy_fixtures import make_rule

SRC = """## 3. 必须拒绝的行为

### 3.1 凭据与敏感数据

- 禁止读取或列举第 2.1 节定义的凭据文件和凭据目录。
- 允许查看本机单个网络接口信息并不等于允许执行网段扫描。
"""


def test_infer_kind_prohibit_is_deny():
    assert infer_kind_from_cues("禁止读取或列举凭据文件和凭据目录") == RuleKind.MANDATORY_DENY


def test_infer_kind_challenge():
    assert infer_kind_from_cues("必须进一步判断") == RuleKind.MUST_CHALLENGE


def test_infer_kind_allow_view():
    assert infer_kind_from_cues("允许查看本机单个网络接口信息并不等于允许执行网段扫描。") == RuleKind.MAY_ALLOW


def test_infer_kind_excludes_not_prohibit_from_deny():
    assert infer_kind_from_cues("不禁止读取本机单个网络接口信息") is None


def test_heading_only_anchor_rejected():
    assert anchor_is_heading_only(SRC, "3.1 凭据与敏感数据") is True
    with pytest.raises(ValueError):
        validate_anchor(SRC, "3.1 凭据与敏感数据")


def test_bullet_substring_anchor_ok():
    validate_anchor(SRC, "禁止读取或列举第 2.1 节定义的凭据文件和凭据目录")


def _rule(kind: RuleKind, anchor: str) -> Rule:
    decision = {
        RuleKind.MANDATORY_DENY: Decision.DENY,
        RuleKind.MUST_CHALLENGE: Decision.CHALLENGE,
        RuleKind.MAY_ALLOW: Decision.ALLOW,
    }[kind]
    return Rule(
        id="R1",
        source_anchor=anchor,
        kind=kind,
        condition=Condition(flag_true=["destructive"]),
        decision=decision,
        priority=Priority.MANDATORY,
        extraction_confidence="high",
    )


def test_rule_kind_uses_containing_bullet_cues():
    rule = _rule(RuleKind.MANDATORY_DENY, "凭据文件和凭据目录")
    validate_rule_kind(rule, SRC, chapter_default=None)


def test_rule_kind_mismatch_raises():
    rule = _rule(RuleKind.MAY_ALLOW, "凭据文件和凭据目录")
    with pytest.raises(ValueError):
        validate_rule_kind(rule, SRC, chapter_default=None)


def test_rule_kind_without_flat_cue_raises():
    rule = _rule(RuleKind.MANDATORY_DENY, "本机单个网络接口")
    with pytest.raises(ValueError):
        validate_rule_kind(rule, "- 本机单个网络接口\n", chapter_default=None)


def test_rule_kind_without_cue_accepts_chapter_default():
    rule = _rule(RuleKind.MANDATORY_DENY, "本机单个网络接口")
    validate_rule_kind(rule, "- 本机单个网络接口\n", chapter_default=RuleKind.MANDATORY_DENY)


def test_validate_extracted_policy_checks_decision_rules():
    policy = Policy(rules=[_rule(RuleKind.MANDATORY_DENY, "凭据文件和凭据目录")])
    validate_extracted_policy(policy, SRC, chapter_default=None)


def test_warn_no_deny_but_prohibit():
    p = Policy(
        rules=[
            make_rule(
                "C1",
                RuleKind.MUST_CHALLENGE,
                operation=[Operation.READ],
                resource_class=[ResourceClass.NORMAL_FILE],
            )
        ]
    )
    src = "禁止\n禁止\n禁止\n禁止\n禁止\n"
    w = collect_quality_warnings(p, src, build_report(p))
    assert W_NO_DENY_BUT_PROHIBIT in w
