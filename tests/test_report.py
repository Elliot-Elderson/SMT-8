from smt_completeness.extractor import load_offline_ir
from smt_completeness.ir import Policy
from smt_completeness.report import ASSUMPTIONS, _format_cube, build_report, render_markdown


def test_build_report_has_no_baseline():
    rep = build_report(load_offline_ir())
    assert not hasattr(rep, "baseline") or "baseline" not in type(rep).model_fields
    assert rep.self_check.ok is True
    assert "A6" not in "".join(ASSUMPTIONS)
    assert any("A8" in a for a in ASSUMPTIONS)


def test_render_markdown_has_unspecified_not_threat_baseline():
    md = render_markdown(build_report(load_offline_ir()), label="before")
    assert "威胁覆盖率" not in md
    assert "真实攻击面" not in md
    assert "V_danger" not in md
    assert "未表态" in md
    assert "V_explicit" in md


def test_compare_section_when_two_reports():
    p = load_offline_ir()
    before = build_report(p)
    md = render_markdown(before, label="after", compare=before)
    assert "补全前后对照" in md


def test_report_includes_defect_sections_and_new_assumptions():
    p = load_offline_ir()
    src = open("Abstract_Access_Control_Requirements.md", encoding="utf-8").read()
    before = build_report(p, source_md=src)
    assert before.defects.silent_permission_volume >= 0
    assert before.evidence.justified_gap_count >= 0
    assert before.clause_coverage is not None
    assert isinstance(before.duplicate_rule_ids, list)
    md = render_markdown(before, label="before")
    assert "缺陷清单" in md
    assert "检出清单" in md
    assert "A9" in md and "A10" in md
    after = build_report(p, source_md=src, initial_policy=p)
    compared = render_markdown(after, label="after", compare=before)
    assert "有依据缺口" in compared
    assert "静默允许" in compared
    assert "仅观察" in compared


def test_observation_top8_lists_fallback_cubes():
    report = build_report(Policy(rules=[]))
    md = render_markdown(report, label="empty")
    top8 = md.split("兜底依赖 Top-8")[1].split("- 未表态体积")[0]
    for cube in report.coverage.fallback_cubes[:8]:
        assert _format_cube(cube) in top8
    fallback_text = {_format_cube(cube) for cube in report.coverage.fallback_cubes[:8]}
    for cube in report.coverage.unspecified_cubes[:8]:
        text = _format_cube(cube)
        if text not in fallback_text:
            assert text not in top8
