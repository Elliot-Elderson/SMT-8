import json
import os
from smt_completeness.cli import run_pipeline
from smt_completeness.extractor import extract, load_offline_ir, self_check


def test_end_to_end_offline(tmp_path):
    out = str(tmp_path / "out")
    result = run_pipeline(
        doc_path="smt_completeness/data/ir_openclaw.yaml",
        out_dir=out,
        complete=True,
        use_llm=False,
        source_doc="Abstract_Access_Control_Requirements.md",
    )
    before_md, before_js, before_smt = result["report_paths"]
    after_md, after_js, after_smt = result["final_report_paths"]
    assert os.path.exists(before_md) and os.path.exists(after_md)
    assert os.path.exists(result["completed_requirements_path"])
    assert os.path.exists(result["final_ir_path"])
    assert os.path.basename(before_smt) == "policy_before.smt2"
    assert os.path.basename(after_smt) == "policy_after.smt2"
    before = json.loads(open(before_js, encoding="utf-8").read())
    after = json.loads(open(after_js, encoding="utf-8").read())
    assert "baseline" not in before
    assert "v_unspecified" in before["coverage"]
    assert "补全前后对照" in open(after_md, encoding="utf-8").read()
    body = open(result["completed_requirements_path"], encoding="utf-8").read()
    assert "必须拒绝" in body
    assert after["coverage"]["v_unspecified"] <= before["coverage"]["v_unspecified"] or after["monotonicity"]["inversion_count"] <= before["monotonicity"]["inversion_count"]


def test_self_check_before_offline_pipeline_keeps_completion_monotone(tmp_path):
    check = self_check(load_offline_ir())
    assert check.ok is True

    out = str(tmp_path / "out")
    result = run_pipeline(
        doc_path="smt_completeness/data/ir_openclaw.yaml",
        out_dir=out,
        complete=True,
        use_llm=False,
        source_doc="Abstract_Access_Control_Requirements.md",
    )
    _, before_js, _ = result["report_paths"]
    _, after_js, _ = result["final_report_paths"]
    before = json.loads(open(before_js, encoding="utf-8").read())
    after = json.loads(open(after_js, encoding="utf-8").read())
    assert after["coverage"]["v_unspecified"] <= before["coverage"]["v_unspecified"] or after["monotonicity"]["inversion_count"] <= before["monotonicity"]["inversion_count"]


def test_rerun_into_same_out_dir(tmp_path):
    out = str(tmp_path / "out")
    for _ in range(2):
        run_pipeline(
            doc_path="smt_completeness/data/ir_openclaw.yaml",
            out_dir=out,
            complete=False,
        )
    assert os.path.exists(os.path.join(out, "report_before.md"))


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


def test_offline_writes_extracted_ir(tmp_path):
    out = str(tmp_path / "out")
    run_pipeline(
        doc_path="smt_completeness/data/ir_openclaw.yaml",
        out_dir=out,
        complete=False,
        use_llm=False,
    )
    ir_path = os.path.join(out, "extracted_ir.yaml")
    qa_path = os.path.join(out, "extract_qa.json")
    assert os.path.isfile(ir_path)
    assert os.path.isfile(qa_path)
    loaded = extract(ir_path, use_llm=False)
    original = extract("smt_completeness/data/ir_openclaw.yaml", use_llm=False)
    assert [r.id for r in loaded.rules] == [r.id for r in original.rules]


def test_from_ir_matches_offline_before(tmp_path):
    out1 = str(tmp_path / "a")
    out2 = str(tmp_path / "b")
    run_pipeline(
        doc_path="smt_completeness/data/ir_openclaw.yaml",
        out_dir=out1,
        complete=False,
    )
    extracted = os.path.join(out1, "extracted_ir.yaml")
    r1 = run_pipeline(
        doc_path="smt_completeness/data/ir_openclaw.yaml",
        out_dir=str(tmp_path / "c"),
        complete=False,
    )
    r2 = run_pipeline(
        doc_path="smt_completeness/data/ir_openclaw.yaml",
        out_dir=out2,
        complete=False,
        from_ir=extracted,
    )
    b1 = json.loads(open(r1["report_paths"][1], encoding="utf-8").read())
    b2 = json.loads(open(r2["report_paths"][1], encoding="utf-8").read())
    assert b1["coverage"]["v_unspecified"] == b2["coverage"]["v_unspecified"]
    assert b1["monotonicity"]["inversion_count"] == b2["monotonicity"]["inversion_count"]


def test_from_ir_and_use_llm_returns_2():
    rc = __import__("smt_completeness.cli", fromlist=["main"]).main(
        [
            "--doc",
            "smt_completeness/data/ir_openclaw.yaml",
            "--from-ir",
            "smt_completeness/data/ir_openclaw.yaml",
            "--use-llm",
            "--no-complete",
        ]
    )
    assert rc == 2
