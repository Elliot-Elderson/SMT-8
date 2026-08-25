import json
import os

import yaml

from smt_completeness.analysis.defects import check_defects
from smt_completeness.analysis.evidence import enumerate_justified_gaps
from smt_completeness.cli import NonRegressionError, run_pipeline
from smt_completeness.completion import CompletionResult
from smt_completeness.extractor import extract, load_offline_ir, self_check
from smt_completeness.ir import Policy


def _load_policy(path: str) -> Policy:
    return Policy.model_validate(yaml.safe_load(open(path, encoding="utf-8")))


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
    assert "本次补全摘要" in body
    assert "不回归保证" in open(after_md, encoding="utf-8").read()
    initial = _load_policy(result["extracted_ir_path"])
    final = _load_policy(result["final_ir_path"])
    assert {r.id for r in initial.rules} <= {r.id for r in final.rules}
    assert len(final.rules) >= len(initial.rules)
    gap_before = enumerate_justified_gaps(initial).justified_gap_count
    gap_after = enumerate_justified_gaps(final).justified_gap_count
    silent_before = check_defects(initial).silent_permission_volume
    silent_after = check_defects(final).silent_permission_volume
    assert gap_after <= gap_before and silent_after <= silent_before
    assert gap_after < gap_before or silent_after < silent_before


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
    initial = _load_policy(result["extracted_ir_path"])
    final = _load_policy(result["final_ir_path"])
    assert {r.id for r in initial.rules} <= {r.id for r in final.rules}
    assert len(final.rules) >= len(initial.rules)
    gap_before = enumerate_justified_gaps(initial).justified_gap_count
    gap_after = enumerate_justified_gaps(final).justified_gap_count
    silent_before = check_defects(initial).silent_permission_volume
    silent_after = check_defects(final).silent_permission_volume
    assert gap_after <= gap_before and silent_after <= silent_before
    assert gap_after < gap_before or silent_after < silent_before


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


def test_llm_pipeline_records_returned_extraction_mode(monkeypatch, tmp_path):
    from smt_completeness.ir import Policy, RuleKind
    from smt_completeness.vocab import Operation, ResourceClass
    from tests.policy_fixtures import make_rule

    policy = Policy(
        rules=[
            make_rule(
                "R3.1",
                RuleKind.MANDATORY_DENY,
                operation=[Operation.READ],
                resource_class=[ResourceClass.NORMAL_FILE],
            )
        ]
    )

    def fake_extract(*args, **kwargs):
        return policy, "chapter"

    monkeypatch.setattr("smt_completeness.cli.extract", fake_extract)
    src = tmp_path / "src.md"
    src.write_text("- 禁止读取普通文件。\n", encoding="utf-8")

    result = run_pipeline(
        doc_path=str(src),
        out_dir=str(tmp_path / "out"),
        complete=False,
        use_llm=True,
        source_doc=str(src),
    )

    qa = json.loads(open(result["extract_qa_path"], encoding="utf-8").read())
    assert qa["extraction_mode"] == "chapter"


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


def test_quality_gate_skips_completion(monkeypatch, tmp_path):
    import yaml

    from smt_completeness.ir import Policy, RuleKind
    from smt_completeness.vocab import Operation, ResourceClass
    from tests.policy_fixtures import make_rule

    called = {"n": 0}

    def boom(policy):
        called["n"] += 1
        raise AssertionError("run_completion must not be called")

    monkeypatch.setattr("smt_completeness.cli.run_completion", boom)
    policy = Policy(
        rules=[
            make_rule(
                "C1",
                RuleKind.MUST_CHALLENGE,
                operation=[Operation.READ],
                resource_class=[ResourceClass.NORMAL_FILE],
            )
        ]
    )
    irp = tmp_path / "only_chal.yaml"
    irp.write_text(
        yaml.safe_dump(policy.model_dump(mode="json"), allow_unicode=True),
        encoding="utf-8",
    )
    src = tmp_path / "src.md"
    src.write_text("禁止\n禁止\n禁止\n禁止\n禁止\n", encoding="utf-8")
    out = str(tmp_path / "out")
    run_pipeline(
        doc_path=str(irp),
        out_dir=out,
        complete=True,
        source_doc=str(src),
    )
    assert called["n"] == 0
    assert os.path.isfile(os.path.join(out, "extracted_ir.yaml"))
    assert os.path.isfile(os.path.join(out, "report_before.md"))
    assert not os.path.isfile(os.path.join(out, "final_ir.yaml"))


def test_non_regression_failure_skips_completed_md(tmp_path, monkeypatch):
    def fake_run(policy, max_rounds=8):
        return CompletionResult(
            rounds=[],
            final_policy=policy,
            converged=True,
            initial_policy=policy,
        )

    def fake_patch(source_md, initial, final, **kwargs):
        dropped = "\n".join(source_md.splitlines()[1:])
        from smt_completeness.nl_patch import PatchStats
        return dropped, PatchStats(
            added=0, dead_annotated=0, duplicate_annotated=0,
            source_lines=len(source_md.splitlines()), added_lines=0,
        )

    monkeypatch.setattr("smt_completeness.cli.run_completion", fake_run)
    monkeypatch.setattr("smt_completeness.cli.apply_nl_patch", fake_patch)
    out = str(tmp_path / "out")
    try:
        run_pipeline(
            doc_path="smt_completeness/data/ir_openclaw.yaml",
            out_dir=out,
            complete=True,
            use_llm=False,
            source_doc="Abstract_Access_Control_Requirements.md",
        )
        raised = False
    except NonRegressionError:
        raised = True
    assert raised is True
    assert os.path.exists(os.path.join(out, "report_after.md"))
    assert not os.path.exists(os.path.join(out, "completed_requirements.md"))
