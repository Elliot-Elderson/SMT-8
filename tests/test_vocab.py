from smt_completeness.vocab import (
    Operation, ResourceClass, TargetZone, Decision,
    RISK_FEATURES, TAINT_FEATURES, ALL_FLAGS, sensitivity_rank,
)


def test_decision_ordering_is_strictness():
    assert Decision.ALLOW < Decision.CHALLENGE < Decision.DENY


def test_flags_are_nine_unique():
    assert len(RISK_FEATURES) == 6
    assert len(TAINT_FEATURES) == 3
    assert ALL_FLAGS == RISK_FEATURES + TAINT_FEATURES
    assert len(set(ALL_FLAGS)) == 9


def test_sensitivity_context_equals_memory():
    # spec §5.5：agent_private_context 与 agent_memory 同级
    assert sensitivity_rank(ResourceClass.AGENT_PRIVATE_CONTEXT) == \
        sensitivity_rank(ResourceClass.AGENT_MEMORY)
    assert sensitivity_rank(ResourceClass.CREDENTIAL) > \
        sensitivity_rank(ResourceClass.NORMAL_FILE)
    assert sensitivity_rank(ResourceClass.EXTERNAL_SERVICE) is None
