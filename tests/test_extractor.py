import pytest

from smt_completeness.extractor import _extract_with_llm, load_offline_ir, self_check, extract
from smt_completeness.ir import Rule, RuleKind, Priority, Condition, Policy, Provenance
from smt_completeness.llm_client import EXTRACT_TEMPERATURE
from smt_completeness.vocab import Decision, Operation, ResourceClass, TargetZone


def test_offline_ir_loads_and_passes_self_check():
    p = load_offline_ir()
    assert len(p.rules) == 24
    rep = self_check(p)
    assert rep.ok is True
    assert rep.id_unique is True
    assert rep.vacuous_rule_ids == []


def test_self_check_rejects_empty_policy():
    rep = self_check(Policy(rules=[]))
    assert rep.ok is False
    assert rep.total_rules == 0


def test_self_check_detects_match_tautology():
    r = Rule.model_construct(
        id="T",
        source_anchor="没有已有策略完整匹配时进入兜底",
        kind=RuleKind.MUST_CHALLENGE,
        condition=Condition(),
        decision=Decision.CHALLENGE,
        priority=Priority.MANDATORY,
        extraction_confidence="high",
        reviewer_status="auto_approved",
        provenance=Provenance.EXTRACTED,
    )
    rep = self_check(Policy.model_construct(rules=[r]))
    assert "T" in rep.tautology_rule_ids
    assert rep.ok is False


def test_self_check_detects_duplicate_id():
    r = Rule(id="X", source_anchor="s", kind=RuleKind.MANDATORY_DENY,
             condition=Condition(flag_true=["destructive"]),
             decision=Decision.DENY, priority=Priority.MANDATORY,
             extraction_confidence="high")
    p = Policy(rules=[r, r.model_copy()])
    rep = self_check(p)
    assert rep.id_unique is False
    assert rep.duplicate_ids == ["X"]


def test_self_check_detects_vacuous_rule():
    r = Rule(id="V", source_anchor="s", kind=RuleKind.MANDATORY_DENY,
             condition=Condition(flag_true=["destructive"],
                                 flag_false=["destructive"]),
             decision=Decision.DENY, priority=Priority.MANDATORY,
             extraction_confidence="high")
    p = Policy(rules=[r])
    rep = self_check(p)
    assert "V" in rep.vacuous_rule_ids
    assert rep.ok is False


def test_extract_offline_returns_policy():
    p = extract("smt_completeness/data/ir_openclaw.yaml", use_llm=False)
    assert isinstance(p, Policy)
    assert len(p.rules) == 24


def test_extract_non_yaml_without_llm_raises():
    with pytest.raises(ValueError, match="离线模式仅支持 YAML IR"):
        extract("README.md", use_llm=False)


def _decision_rule(id: str, kind: RuleKind, anchor: str) -> Rule:
    decision = {
        RuleKind.MANDATORY_DENY: Decision.DENY,
        RuleKind.MUST_CHALLENGE: Decision.CHALLENGE,
        RuleKind.MAY_ALLOW: Decision.ALLOW,
    }[kind]
    return Rule(
        id=id,
        source_anchor=anchor,
        kind=kind,
        condition=Condition(
            operation=[Operation.READ],
            resource_class=[ResourceClass.NORMAL_FILE],
            target_zone=[TargetZone.LOCAL],
        ),
        decision=decision,
        priority=Priority.MANDATORY,
        extraction_confidence="high",
    )


def _install_fake_client(monkeypatch, calls, policies):
    class _Completions:
        def create(self, **kwargs):
            calls.append(kwargs)
            assert kwargs["temperature"] == EXTRACT_TEMPERATURE
            assert kwargs["max_retries"] == 3
            return policies[len(calls) - 1]

    class _Client:
        chat = type("_Chat", (), {"completions": _Completions()})()

    monkeypatch.setattr(
        "smt_completeness.llm_client.build_instructor_client",
        lambda provider: _Client(),
    )
    monkeypatch.setattr(
        "smt_completeness.llm_client.resolve_model",
        lambda provider, model: "test-model",
    )


def test_extract_with_llm_empty_rules_raises(monkeypatch, tmp_path):
    doc = tmp_path / "source.md"
    doc.write_text("- 禁止读取凭据文件。\n", encoding="utf-8")
    calls = []
    _install_fake_client(monkeypatch, calls, [Policy(rules=[])])

    with pytest.raises(ValueError, match="抽取结果为空规则表"):
        extract(str(doc), use_llm=True)


def test_extract_with_llm_splits_three_chapters_and_renumbers(monkeypatch, tmp_path):
    doc = tmp_path / "chapters.md"
    doc.write_text(
        "\n".join(
            [
                "# x",
                "## 3. 必须拒绝的行为",
                "- 禁止读取或列举第 2.1 节定义的凭据文件和凭据目录。",
                "## 4. 必须进一步判断的行为",
                "- 普通本地文件发送到外部或未知目标。",
                "## 5. 可以保留的正常工作流",
                "- 在本地读取普通文件或源代码。",
                "## 6. 系统如何执行这些要求",
                "- 不应进入抽取章节。",
            ]
        ),
        encoding="utf-8",
    )
    calls = []
    _install_fake_client(
        monkeypatch,
        calls,
        [
            Policy(
                rules=[
                    _decision_rule(
                        "old1",
                        RuleKind.MANDATORY_DENY,
                        "禁止读取或列举第 2.1 节定义的凭据文件和凭据目录",
                    )
                ]
            ),
            Policy(
                rules=[
                    _decision_rule(
                        "old2",
                        RuleKind.MUST_CHALLENGE,
                        "普通本地文件发送到外部或未知目标",
                    )
                ]
            ),
            Policy(
                rules=[
                    _decision_rule(
                        "old3",
                        RuleKind.MAY_ALLOW,
                        "在本地读取普通文件或源代码",
                    )
                ]
            ),
        ],
    )

    policy, mode = _extract_with_llm(str(doc), provider="openai")

    assert mode == "chapter"
    assert [rule.id for rule in policy.rules] == ["R3.1", "R4.1", "R5.1"]
    assert len(calls) == 3
    prompts = [call["messages"][0]["content"] for call in calls]
    assert "本段默认 kind 为 mandatory_deny" in prompts[0]
    assert "本段默认 kind 为 must_challenge" in prompts[1]
    assert "本段默认 kind 为 may_allow" in prompts[2]
    assert all("ir_openclaw.yaml" not in prompt for prompt in prompts)


def test_extract_with_llm_flat_fallback_calls_once(monkeypatch, tmp_path):
    doc = tmp_path / "flat.md"
    doc.write_text("- 禁止读取凭据文件。\n", encoding="utf-8")
    calls = []
    _install_fake_client(
        monkeypatch,
        calls,
        [
            Policy(
                rules=[
                    _decision_rule(
                        "old",
                        RuleKind.MANDATORY_DENY,
                        "禁止读取凭据文件",
                    )
                ]
            )
        ],
    )

    policy, mode = _extract_with_llm(str(doc), provider="openai")

    assert mode == "flat"
    assert [rule.id for rule in policy.rules] == ["R.1"]
    assert len(calls) == 1
    prompt = calls[0]["messages"][0]["content"]
    assert "本段默认 kind" not in prompt


def test_extract_with_llm_validates_policy_before_return(monkeypatch, tmp_path):
    doc = tmp_path / "source.md"
    doc.write_text("- 禁止读取凭据文件。\n", encoding="utf-8")
    invalid_policy = Policy(
        rules=[
            Rule(
                id="R1",
                source_anchor="缺失的原文锚点至少八个字",
                kind=RuleKind.MANDATORY_DENY,
                condition=Condition(flag_true=["destructive"]),
                decision=Decision.DENY,
                priority=Priority.MANDATORY,
                extraction_confidence="high",
            )
        ]
    )

    class _Completions:
        def create(self, **kwargs):
            return invalid_policy

    class _Client:
        chat = type("_Chat", (), {"completions": _Completions()})()

    monkeypatch.setattr(
        "smt_completeness.llm_client.build_instructor_client",
        lambda provider: _Client(),
    )
    monkeypatch.setattr(
        "smt_completeness.llm_client.resolve_model",
        lambda provider, model: "test-model",
    )

    with pytest.raises(ValueError, match="source_anchor"):
        _extract_with_llm(str(doc), provider="openai")


def test_vacuity_does_not_import_all_states_on_extractor():
    import smt_completeness.extractor as ext
    src = open(ext.__file__, encoding="utf-8").read()
    assert "all_states" not in src
