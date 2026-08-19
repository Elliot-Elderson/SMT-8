import json
import os

from smt_completeness.cli import run_pipeline


def test_end_to_end_offline(tmp_path):
    out = str(tmp_path / "out")
    result = run_pipeline(
        doc_path="smt_completeness/data/ir_openclaw.yaml",
        out_dir=out,
        complete=True,
        use_llm=False,
    )
    md, js, smt = result["report_paths"]
    assert os.path.exists(md) and os.path.exists(js) and os.path.exists(smt)
    data = json.loads(open(js, encoding="utf-8").read())
    assert data["baseline"]["total"] == 18
    # 闭环后应有最终报告，且 V_danger 不增
    assert result["completion"] is not None
    final_md, final_js, _ = result["final_report_paths"]
    assert os.path.exists(final_md)
    before = json.loads(open(js, encoding="utf-8").read())["coverage"]["v_danger"]
    after = json.loads(open(final_js, encoding="utf-8").read())["coverage"]["v_danger"]
    assert after <= before


def test_main_returns_zero(tmp_path):
    rc = __import__("smt_completeness.cli", fromlist=["main"]).main(
        [
            "--doc",
            "smt_completeness/data/ir_openclaw.yaml",
            "--out",
            str(tmp_path / "o"),
            "--no-complete",
        ]
    )
    assert rc == 0


def test_main_accepts_deepseek_provider_offline(tmp_path):
    # offline path: provider flag is accepted even when --use-llm is off
    rc = __import__("smt_completeness.cli", fromlist=["main"]).main(
        [
            "--doc",
            "smt_completeness/data/ir_openclaw.yaml",
            "--out",
            str(tmp_path / "o2"),
            "--no-complete",
            "--llm-provider",
            "deepseek",
        ]
    )
    assert rc == 0
