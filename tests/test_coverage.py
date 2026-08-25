from smt_completeness.analysis.coverage import check_coverage
from smt_completeness.ir import Policy, RuleKind
from smt_completeness.state_space import EXPECTED_STATE_COUNT
from smt_completeness.vocab import Operation, TargetZone
from tests.policy_fixtures import deny_destructive, make_rule


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


def _cube_includes_default_allow(cube) -> bool:
    op_ok = not cube.operation or "read" in cube.operation or "list" in cube.operation
    zone_ok = not cube.target_zone or "local" in cube.target_zone
    return op_ok and zone_ok and not cube.flag_true


def test_fallback_cubes_exclude_default_allow():
    empty = check_coverage(Policy(rules=[]))
    assert empty.v_unspecified_allow > 0
    assert empty.fallback_cubes
    assert empty.fallback_cubes != empty.unspecified_cubes
    assert any(_cube_includes_default_allow(cube) for cube in empty.unspecified_cubes)
    assert all(not _cube_includes_default_allow(cube) for cube in empty.fallback_cubes)

    covered = check_coverage(
        Policy(
            rules=[
                make_rule(
                    "A-local",
                    RuleKind.MAY_ALLOW,
                    operation=[Operation.READ, Operation.LIST],
                    target_zone=[TargetZone.LOCAL],
                )
            ]
        )
    )
    assert covered.v_unspecified_allow == 0
    assert covered.v_unspecified_challenge > 0
    assert covered.fallback_cubes
    assert all(not _cube_includes_default_allow(cube) for cube in covered.fallback_cubes)
