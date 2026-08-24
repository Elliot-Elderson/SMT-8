from smt_completeness.bdd_env import BDDEnv
from smt_completeness.ir import Policy
from smt_completeness.state_space import EXPECTED_STATE_COUNT
from smt_completeness.vocab import Decision
from tests.policy_fixtures import deny_destructive, deny_read_private_context


def test_valid_count_is_expected_state_count():
    env = BDDEnv(Policy(rules=[]))
    assert env.count(env.valid) == EXPECTED_STATE_COUNT == 122880


def test_empty_policy_default_allow_volume_is_read_list_local_no_flags():
    env = BDDEnv(Policy(rules=[]))
    n = env.count(env.default_allow() & env.valid)
    # 2 ops (read,list) * 10 rc * 1 zone * 1 flag-assignment
    assert n == 20


def test_destructive_deny_makes_those_states_d_eq_deny():
    env = BDDEnv(Policy(rules=[deny_destructive()]))
    deny = env.d_is(int(Decision.DENY))
    # 所有 destructive=true 的合法状态
    assert env.count(deny & env.valid) == 6 * 10 * 4 * (2 ** 8)


def test_count_positive_iff_match_nonempty():
    env = BDDEnv(Policy(rules=[deny_read_private_context()]))
    m = env.match_rule(deny_read_private_context())
    assert env.count(m & env.valid) > 0
