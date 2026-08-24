from smt_completeness.compiler import (
    decide_py,
    find_decision_diff,
    is_monotone,
    is_vacuous,
    policies_equivalent,
    preserves_mustallow,
)
from smt_completeness.ir import Policy, RuleKind
from smt_completeness.vocab import Operation, ResourceClass
from tests.policy_fixtures import (
    allow_read_normal_local,
    deny_destructive,
    deny_read_private_context,
    make_rule,
)


def test_duplicate_rules_are_equivalent_if_one_dropped():
    r = deny_destructive()
    a = Policy(rules=[r, r.model_copy(update={"id": "D2"})])
    b = Policy(rules=[r])
    assert policies_equivalent(a, b) is True


def test_adding_unrelated_allow_is_not_monotone():
    old = Policy(rules=[deny_destructive()])
    extra = make_rule(
        "LOOSE",
        RuleKind.MAY_ALLOW,
        operation=[Operation.EXECUTE],
        resource_class=[ResourceClass.UNKNOWN],
    )
    new = Policy(rules=old.rules + [extra])
    assert is_monotone(old, new) is False


def test_find_decision_diff_returns_python_observable_witness():
    a = Policy(rules=[deny_destructive()])
    extra = make_rule(
        "LOOSE",
        RuleKind.MAY_ALLOW,
        operation=[Operation.EXECUTE],
        resource_class=[ResourceClass.UNKNOWN],
    )
    b = Policy(rules=a.rules + [extra])
    witness = find_decision_diff(a, b)
    assert witness is not None
    assert decide_py(witness, a) != decide_py(witness, b)


def test_adding_deny_is_monotone_and_preserves_unrelated_mustallow():
    old = Policy(rules=[allow_read_normal_local()])
    new = Policy(rules=old.rules + [deny_read_private_context()])
    assert is_monotone(old, new) is True
    assert preserves_mustallow(old, new) is True


def test_contradictory_flags_are_vacuous():
    r = make_rule(
        "V",
        RuleKind.MANDATORY_DENY,
        flag_true=["destructive"],
        flag_false=["destructive"],
    )
    assert is_vacuous(Policy(rules=[r]), r) is True
