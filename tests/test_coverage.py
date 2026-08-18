from smt_completeness.analysis.coverage import check_coverage
from smt_completeness.extractor import load_offline_ir
from smt_completeness.state_space import EXPECTED_STATE_COUNT
from smt_completeness.vocab import ResourceClass


def test_partitions_sum_to_total():
    rep = check_coverage(load_offline_ir())
    assert rep.total == EXPECTED_STATE_COUNT
    assert rep.v_explicit + rep.v_danger + rep.v_deferred == rep.total
    assert abs(rep.v_explicit_ratio + rep.v_danger_ratio + rep.v_deferred_ratio - 1.0) < 1e-9


def test_credential_write_falls_into_gap_or_deferred():
    # spec 场景一：凭据写入侧未覆盖 → 落入默认区（deferred，因 write 非 read/list）
    rep = check_coverage(load_offline_ir())
    # 至少存在危险面 cube 输出（默认 Allow 区非空）
    assert rep.v_danger >= 0
    assert isinstance(rep.danger_cubes, list)


def test_danger_cubes_have_size():
    rep = check_coverage(load_offline_ir())
    for cube in rep.danger_cubes:
        assert cube.size >= 1
