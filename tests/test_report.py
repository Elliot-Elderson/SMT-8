import json

from smt_completeness.extractor import load_offline_ir
from smt_completeness.report import ASSUMPTIONS, build_report, render_markdown, write_reports


def test_build_report_has_all_sections():
    rep = build_report(load_offline_ir())
    assert rep.self_check.ok is True
    assert rep.coverage.total > 0
    assert rep.baseline.total == 18
    assert len(rep.assumptions) == 7


def test_render_markdown_contains_key_metrics():
    md = render_markdown(build_report(load_offline_ir()))
    assert "威胁覆盖率" in md
    assert "V_danger" in md
    assert "threats to validity" in md.lower() or "威胁有效性" in md


def test_write_reports_creates_three_files(tmp_path):
    md_path, json_path, smt_path = write_reports(load_offline_ir(), str(tmp_path))
    assert md_path.endswith(".md")
    data = json.loads(open(json_path, encoding="utf-8").read())
    assert "coverage" in data
    assert open(smt_path, encoding="utf-8").read()
    assert len(ASSUMPTIONS) == 7
