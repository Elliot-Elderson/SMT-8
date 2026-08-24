from smt_completeness.extractor import load_offline_ir
from smt_completeness.report import ASSUMPTIONS, build_report, render_markdown


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
