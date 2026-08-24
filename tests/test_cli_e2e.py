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
        source_doc="Abstract_Access_Control_Requirements.md",
    )
    before_md, before_js, _ = result["report_paths"]
    after_md, after_js, _ = result["final_report_paths"]
    assert os.path.exists(before_md) and os.path.exists(after_md)
    assert os.path.exists(result["completed_requirements_path"])
    assert os.path.exists(result["final_ir_path"])
    before = json.loads(open(before_js, encoding="utf-8").read())
    after = json.loads(open(after_js, encoding="utf-8").read())
    assert "baseline" not in before
    assert "v_unspecified" in before["coverage"]
    assert "补全前后对照" in open(after_md, encoding="utf-8").read()
    body = open(result["completed_requirements_path"], encoding="utf-8").read()
    assert "必须拒绝" in body
    assert after["coverage"]["v_unspecified"] <= before["coverage"]["v_unspecified"] or after["monotonicity"]["inversion_count"] <= before["monotonicity"]["inversion_count"]


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
