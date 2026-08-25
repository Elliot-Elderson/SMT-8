import argparse
import hashlib
import os

import yaml

from .compiler import is_monotone, preserves_mustallow
from .completion import run_completion
from .extractor import (
    build_extract_qa,
    extract,
    load_offline_ir,
    self_check,
    write_extract_qa,
    write_extracted_ir,
)
from .extract_validate import collect_quality_warnings
from .ir import Policy
from .nl_patch import apply_nl_patch, original_lines_preserved
from .report import build_report, render_markdown, write_policy_reports


class NonRegressionError(ValueError):
    """Raised when post-completion non-regression guarantees fail."""


def _non_regression_result(
    initial: Policy,
    final: Policy,
    source_md: str,
    patched_text: str,
) -> tuple[dict, list[str]]:
    monotone_ok = is_monotone(initial, final)
    mustallow_ok = preserves_mustallow(initial, final)
    preserved, n_src, n_added = original_lines_preserved(source_md, patched_text)
    initial_ids = {rule.id for rule in initial.rules}
    final_ids = {rule.id for rule in final.rules}
    ids_ok = initial_ids <= final_ids and len(final.rules) >= len(initial.rules)

    reasons: dict[str, str] = {}
    if not monotone_ok:
        reasons["monotone"] = "存在状态从 Deny/Challenge 放宽为 Allow"
    if not mustallow_ok:
        reasons["mustallow"] = "MustAllow 状态被新规则破坏"
    if not preserved:
        reasons["original_lines"] = "原文有行未按序出现在补丁文档中"
    if not ids_ok:
        missing = sorted(initial_ids - final_ids)
        reasons["ids_preserved"] = f"初始规则 id 未全部保留：{missing}"

    payload = {
        "monotone": monotone_ok,
        "mustallow": mustallow_ok,
        "original_lines": preserved,
        "ids_preserved": ids_ok,
        "source_lines": n_src,
        "added_lines": n_added,
        "reasons": reasons,
    }
    labels = {
        "monotone": "单调性",
        "mustallow": "MustAllow 保持",
        "original_lines": "原文逐行保留",
        "ids_preserved": "条款只增不减",
    }
    failed = [
        f"{labels[key]}（{reasons[key]}）"
        for key in labels
        if not payload[key]
    ]
    return payload, failed


def _rename_smt_export(
    paths: tuple[str, str, str], out_dir: str, smt_name: str
) -> tuple[str, str, str]:
    md_path, json_path, smt_path = paths
    new_smt_path = os.path.join(out_dir, smt_name)
    os.replace(smt_path, new_smt_path)
    return md_path, json_path, new_smt_path


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_pipeline(
    doc_path: str,
    out_dir: str,
    complete: bool = True,
    use_llm: bool = False,
    llm_provider: str = "openai",
    llm_model: str | None = None,
    source_doc: str | None = None,
    from_ir: str | None = None,
    force_complete: bool = False,
) -> dict:
    if from_ir and use_llm:
        raise ValueError("--from-ir 不能与 --use-llm 同时使用")

    if source_doc is None:
        source_doc = "Abstract_Access_Control_Requirements.md"

    if complete and not os.path.isfile(source_doc):
        raise FileNotFoundError(
            f"源需求文档未找到：{source_doc!r}。"
            "请用 --source-doc 指定路径，或用 --no-complete 跳过补全闭环。"
        )

    loaded_source = from_ir or doc_path
    if from_ir:
        policy = load_offline_ir(from_ir)
        extraction_mode = "offline"
        provider = None
        model = None
    else:
        extracted = extract(
            doc_path,
            use_llm=use_llm,
            provider=llm_provider,
            model=llm_model,
            return_mode=True,
        )
        policy, extraction_mode = extracted
        provider = llm_provider if use_llm else None
        model = llm_model if use_llm else None

    check = self_check(policy)
    os.makedirs(out_dir, exist_ok=True)
    qa = build_extract_qa(
        policy=policy,
        source_doc=loaded_source,
        source_sha256=_sha256_file(loaded_source),
        self_check=check,
        provider=provider,
        model=model,
        extraction_mode=extraction_mode,
        skipped_completion=not complete,
    )

    if not check.ok:
        write_extract_qa(qa, os.path.join(out_dir, "extract_qa.json"))
        raise ValueError(
            "IR 自检未通过："
            f"重复 id={check.duplicate_ids}，"
            f"恒假规则={check.vacuous_rule_ids}，"
            f"恒真规则={check.tautology_rule_ids}"
        )

    extracted_ir_path = os.path.join(out_dir, "extracted_ir.yaml")
    extract_qa_path = os.path.join(out_dir, "extract_qa.json")
    write_extracted_ir(policy, extracted_ir_path)
    write_extract_qa(qa, extract_qa_path)

    source_md = None
    if complete:
        with open(source_doc, encoding="utf-8") as f:
            source_md = f.read()

    before = build_report(policy, source_md=source_md)
    if complete:
        qa.warnings = collect_quality_warnings(policy, source_md, before)
        if qa.warnings and not force_complete:
            qa.skipped_completion = True
            print(f"[警告] 抽取质量警告: {', '.join(qa.warnings)}")
            print("[警告] 已跳过补全，使用 --force-complete 强制")
        write_extract_qa(qa, extract_qa_path)

    report_paths = _rename_smt_export(
        write_policy_reports(policy, out_dir, "report_before", report=before, qa=qa),
        out_dir,
        "policy_before.smt2",
    )

    completion = None
    final_report_paths = None
    completed_requirements_path = None
    final_ir_path = None

    if complete and not qa.skipped_completion:
        result = run_completion(policy.model_copy(deep=True))
        completion = result
        final_policy = result.final_policy
        after = build_report(
            final_policy,
            source_md=source_md,
            initial_policy=result.initial_policy,
        )
        patched_text, _stats = apply_nl_patch(
            source_md, result.initial_policy, final_policy
        )
        nr, failed = _non_regression_result(
            result.initial_policy, final_policy, source_md, patched_text
        )

        final_report_paths = _rename_smt_export(
            write_policy_reports(final_policy, out_dir, "report_after", report=after),
            out_dir,
            "policy_after.smt2",
        )
        after_md_path = final_report_paths[0]
        with open(after_md_path, "w", encoding="utf-8") as f:
            f.write(
                render_markdown(
                    after,
                    label="after",
                    compare=before,
                    completion=result,
                    non_regression=nr,
                )
            )

        final_ir_path = os.path.join(out_dir, "final_ir.yaml")
        with open(final_ir_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(final_policy.model_dump(mode="json"), f, allow_unicode=True)

        if failed:
            raise NonRegressionError("不回归保证失败：" + "；".join(failed))

        completed_requirements_path = os.path.join(out_dir, "completed_requirements.md")
        with open(completed_requirements_path, "w", encoding="utf-8") as f:
            f.write(patched_text)

    return {
        "report_paths": report_paths,
        "final_report_paths": final_report_paths,
        "completion": completion,
        "completed_requirements_path": completed_requirements_path,
        "final_ir_path": final_ir_path,
        "extracted_ir_path": extracted_ir_path,
        "extract_qa_path": extract_qa_path,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Agent 访问控制需求完备性检查器（MVP demo）"
    )
    parser.add_argument("--doc", required=False, help="需求文档或离线 IR(.yaml) 路径")
    parser.add_argument("--out", default="out", help="报告输出目录")
    parser.add_argument("--no-complete", action="store_true", help="跳过 IR 补全闭环，只输出分析报告")
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="启用真实 LLM 抽取（openai 需 OPENAI_API_KEY；deepseek 需 DEEPSEEK_API_KEY）",
    )
    parser.add_argument(
        "--llm-provider",
        choices=["openai", "deepseek"],
        default="openai",
        help="LLM 提供方（默认 openai；可选 deepseek）",
    )
    parser.add_argument(
        "--llm-model",
        default=None,
        help="覆盖默认模型（openai 默认 gpt-4o；deepseek 默认 deepseek-chat）",
    )
    parser.add_argument(
        "--source-doc",
        default="Abstract_Access_Control_Requirements.md",
        help="源需求文档（用于 NL 补丁，默认 Abstract_Access_Control_Requirements.md）",
    )
    parser.add_argument(
        "--polish-nl",
        action="store_true",
        help="（保留选项）NL 润色，当前忽略",
    )
    parser.add_argument("--from-ir", default=None, help="从已冻结的 YAML IR 继续运行")
    parser.add_argument(
        "--force-complete",
        action="store_true",
        help="强制进入补全闭环（Task 6 生效，当前仅接线）",
    )
    args = parser.parse_args(argv)

    if not args.doc and not args.from_ir:
        print("[错误] 缺少 --doc；除非提供 --from-ir")
        return 2
    if args.from_ir and args.use_llm:
        print("[错误] --from-ir 不能与 --use-llm 同时使用")
        return 2

    try:
        result = run_pipeline(
            doc_path=args.doc or args.from_ir,
            out_dir=args.out,
            complete=not args.no_complete,
            use_llm=args.use_llm,
            llm_provider=args.llm_provider,
            llm_model=args.llm_model,
            source_doc=args.source_doc,
            from_ir=args.from_ir,
            force_complete=args.force_complete,
        )
    except ValueError as exc:
        print(f"[错误] {exc}")
        return 2

    md, js, smt = result["report_paths"]
    print(f"[报告] Markdown: {md}")
    print(f"[报告] JSON:     {js}")
    print(f"[产物] SMT-LIB:  {smt}")
    if result["completion"] is not None:
        c = result["completion"]
        print(f"[补全] 轮数={len(c.rounds)} 收敛={c.converged}")
        if result["final_report_paths"]:
            print(f"[补全后报告] {result['final_report_paths'][0]}")
        if result["completed_requirements_path"]:
            print(f"[补全需求] {result['completed_requirements_path']}")
        if result["final_ir_path"]:
            print(f"[最终 IR] {result['final_ir_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
