from smt_completeness.bdd_env import BDDEnv
from smt_completeness.cubes import MAX_LITERALS, generalize, literal_count
from smt_completeness.ir import Policy
from smt_completeness.state_space import State
from smt_completeness.vocab import Operation, ResourceClass, TargetZone
from tests.policy_fixtures import deny_destructive


def test_generalize_drops_irrelevant_flags_on_unspecified():
    env = BDDEnv(Policy(rules=[deny_destructive()]))
    p = env.valid & ~env.any_match()
    seed = State(
        Operation.READ,
        ResourceClass.NORMAL_FILE,
        TargetZone.LOCAL,
        frozenset(),
    )
    cube = generalize(env, seed, p)
    assert cube is not None
    assert literal_count(cube) <= MAX_LITERALS
    assert cube.flag_true == []
    assert "destructive" not in cube.flag_false or cube.flag_false == ["destructive"]
    # 无 destructive 时未表态；flag_false 最多保留 destructive
    assert set(cube.flag_false) <= {"destructive"}


def test_generalize_none_when_seed_not_in_target():
    env = BDDEnv(Policy(rules=[deny_destructive()]))
    p = env.valid & env.d_is(2)
    seed = State(Operation.READ, ResourceClass.NORMAL_FILE, TargetZone.LOCAL, frozenset())
    assert generalize(env, seed, p) is None
