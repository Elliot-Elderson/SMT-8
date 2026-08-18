from smt_completeness.extractor import load_offline_ir
from smt_completeness.threats.baseline import check_baseline, load_seed


def test_seed_loads():
    seed = load_seed()
    assert len(seed) == 18


def test_covered_and_gaps_partition():
    rep = check_baseline(load_offline_ir())
    assert rep.total == 18
    assert rep.covered + rep.requirement_gaps + rep.vocab_gaps == rep.total
    assert 0.0 <= rep.coverage_ratio <= 1.0


def test_credential_write_is_requirement_gap():
    rep = check_baseline(load_offline_ir())
    ids = {g.id: g for g in rep.gaps}
    assert "TINV-CRED-18" in ids
    assert ids["TINV-CRED-18"].kind == "requirement_gap"
    assert ids["TINV-CRED-18"].example_state is not None


def test_llm_rendering_is_vocab_gap():
    rep = check_baseline(load_offline_ir())
    ids = {g.id: g for g in rep.gaps}
    assert "TINV-EXFIL-07" in ids
    assert ids["TINV-EXFIL-07"].kind == "vocab_gap"


def test_covered_invariant_not_in_gaps():
    rep = check_baseline(load_offline_ir())
    gap_ids = {g.id for g in rep.gaps}
    assert "TINV-CRED-01" not in gap_ids
