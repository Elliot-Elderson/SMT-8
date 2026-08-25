from smt_completeness.analysis.defects import check_defects
from smt_completeness.analysis.evidence import enumerate_justified_gaps
from smt_completeness.compiler import decide_py, is_monotone, preserves_mustallow
from smt_completeness.completion import fix_silent_permissions, run_completion
from smt_completeness.ir import Policy, Provenance, RuleKind
from smt_completeness.state_space import State
from smt_completeness.vocab import ALL_FLAGS, Decision, Operation, ResourceClass, TargetZone
from tests.policy_fixtures import deny_read_private_context, make_rule


def test_completion_is_purely_additive():
    r1 = deny_read_private_context()
    r2 = make_rule(
        "C1",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.SEND],
        resource_class=[ResourceClass.NORMAL_FILE],
    )
    initial = Policy(rules=[r1, r2])
    result = run_completion(initial, max_rounds=3)
    final_ids = {rule.id for rule in result.final_policy.rules}
    assert {r1.id, r2.id} <= final_ids
    assert len(result.final_policy.rules) >= 2
    assert not hasattr(result.rounds[0], "removed_rule_ids")
    assert not hasattr(result.rounds[0], "narrowed_rule_ids")


def test_identical_extracted_rules_are_not_deleted():
    a = make_rule(
        "R4.1",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.WRITE],
        resource_class=[ResourceClass.CONFIG],
    )
    b = make_rule(
        "R4.2",
        RuleKind.MUST_CHALLENGE,
        operation=[Operation.WRITE],
        resource_class=[ResourceClass.CONFIG],
    )
    result = run_completion(Policy(rules=[a, b]), max_rounds=2)
    ids = {rule.id for rule in result.final_policy.rules}
    assert {"R4.1", "R4.2"} <= ids


def test_gap_inherits_evidence_target_zones_not_wildcard():
    evidence = make_rule(
        "R3.6",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.SEND],
        resource_class=[ResourceClass.PRIVATE_DATA],
        target_zone=[TargetZone.EXTERNAL, TargetZone.UNKNOWN],
    )
    result = run_completion(Policy(rules=[evidence]), max_rounds=2)
    syn = [
        rule
        for rule in result.final_policy.rules
        if rule.provenance is Provenance.SYNTHESIZED
        and ResourceClass.SYSTEM_SENSITIVE in rule.condition.resource_class
        and Operation.SEND in rule.condition.operation
    ]
    assert syn
    assert syn[0].condition.target_zone == [TargetZone.EXTERNAL, TargetZone.UNKNOWN]
    assert syn[0].justification is not None
    assert syn[0].justification.defect == "sensitivity_gap"
    assert syn[0].source_anchor == evidence.source_anchor


def test_gap_before_silent_uses_deny_not_second_challenge():
    evidence = deny_read_private_context()
    result = run_completion(Policy(rules=[evidence]), max_rounds=3)
    seed = State(
        Operation.READ, ResourceClass.AGENT_MEMORY, TargetZone.LOCAL, frozenset()
    )
    assert decide_py(seed, result.final_policy) is Decision.DENY
    covering_challenge = [
        rule
        for rule in result.final_policy.rules
        if rule.kind is RuleKind.MUST_CHALLENGE
        and rule.provenance is Provenance.SYNTHESIZED
        and Operation.READ in rule.condition.operation
        and ResourceClass.AGENT_MEMORY in rule.condition.resource_class
        and rule.condition.target_zone == [TargetZone.LOCAL]
    ]
    assert covering_challenge == []


def test_silent_permissions_group_into_challenge_rules():
    evidence = make_rule(
        "D-cred",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
        target_zone=[TargetZone.EXTERNAL],
    )
    before = check_defects(Policy(rules=[evidence])).silent_permission_volume
    result = run_completion(Policy(rules=[evidence]), max_rounds=2)
    after = check_defects(result.final_policy).silent_permission_volume
    assert before > 0
    assert after == 0
    syn_chal = [
        rule
        for rule in result.final_policy.rules
        if rule.justification is not None
        and rule.justification.defect == "silent_permission"
    ]
    assert syn_chal
    assert all(rule.kind is RuleKind.MUST_CHALLENGE for rule in syn_chal)
    assert all(
        bool(rule.condition.operation)
        + bool(rule.condition.resource_class)
        + bool(rule.condition.target_zone)
        + len(rule.condition.flag_true)
        + len(rule.condition.flag_false)
        <= 4
        for rule in syn_chal
    )


def test_completion_keeps_monotone_and_mustallow():
    base = Policy(rules=[deny_read_private_context()])
    result = run_completion(base, max_rounds=5)
    assert is_monotone(base, result.final_policy)
    assert preserves_mustallow(base, result.final_policy)
    syn = [rule for rule in result.final_policy.rules if rule.provenance is Provenance.SYNTHESIZED]
    assert any(ResourceClass.AGENT_MEMORY in rule.condition.resource_class for rule in syn)


def test_stop_metrics_ignore_unspecified_volume():
    evidence = deny_read_private_context()
    result = run_completion(Policy(rules=[evidence]), max_rounds=8)
    last = result.rounds[-1]
    assert hasattr(last, "justified_gap_count_after")
    assert hasattr(last, "silent_permission_volume_after")
    if result.converged:
        assert last.justified_gap_count_after == 0
        assert last.silent_permission_volume_after == 0


def test_mustallow_retry_witness_is_silent_seed():
    others = [flag for flag in ALL_FLAGS if flag != "destructive"]
    floor = make_rule(
        "A-flagged",
        RuleKind.MAY_ALLOW,
        operation=[Operation.READ],
        resource_class=[ResourceClass.NORMAL_FILE],
        target_zone=[TargetZone.LOCAL],
        flag_true=["destructive"],
        flag_false=others,
    )
    current, added, skipped = fix_silent_permissions(Policy(rules=[floor]), 0, [0])
    retried = [
        rule
        for rule in current.rules
        if rule.id in added and rule.condition.flag_false
    ]
    assert skipped
    assert retried
    rule = retried[0]
    assert rule.justification is not None
    assert rule.condition.flag_false
    assert rule.justification.witness["flags"] == []
    assert rule.justification.witness_decision_before == int(Decision.ALLOW)
    assert rule.justification.witness_decision_after == int(Decision.CHALLENGE)


def test_completion_module_has_no_all_states():
    from smt_completeness import completion as m

    assert "all_states" not in open(m.__file__, encoding="utf-8").read()
    assert "_hygiene_phase" not in open(m.__file__, encoding="utf-8").read()
    assert "_covers_default_allow" not in open(m.__file__, encoding="utf-8").read()
