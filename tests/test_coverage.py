from smt_completeness.analysis.coverage import check_coverage
from smt_completeness.ir import Policy
from smt_completeness.state_space import EXPECTED_STATE_COUNT
from tests.policy_fixtures import deny_destructive


def test_empty_policy_unspecified_is_all_states():
    rep = check_coverage(Policy(rules=[]))
    assert rep.total == EXPECTED_STATE_COUNT
    assert rep.v_explicit == 0
    assert rep.v_unspecified == EXPECTED_STATE_COUNT
    assert rep.v_unspecified_allow == 20
    assert rep.v_unspecified_challenge == EXPECTED_STATE_COUNT - 20


def test_destructive_deny_reduces_unspecified():
    rep = check_coverage(Policy(rules=[deny_destructive()]))
    assert rep.v_explicit == 6 * 10 * 4 * (2 ** 8)
    assert rep.v_unspecified == EXPECTED_STATE_COUNT - rep.v_explicit
    assert "v_danger" not in type(rep).model_fields
