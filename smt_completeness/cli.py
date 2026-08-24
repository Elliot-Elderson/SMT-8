import argparse
import os

import yaml

from .completion import run_completion
from .extractor import extract, self_check
from .nl_patch import apply_nl_patch
from .report import FullReport, build_report, render_markdown, write_policy_reports


def _rename_smt_export(
    paths: tuple[str, str, str], out_dir: str, smt_name: str
) -> tuple[str, str, str]:
    md_path, json_path, smt_path = paths
    new_smt_path = os.path.join(out_dir, smt_name)
    os.replace(smt_path, new_smt_path)
    return md_path, json_path, new_smt_path


def run_pipeline(
    doc_path: str,
    out_dir: str,
    complete: bool = True,
    use_llm: bool = False,
    llm_provider: str = "openai",
    llm_model: str | None = None,
    source_doc: str | None = None,
) -> dict:
    if source_doc is None:
        source_doc = "Abstract_Access_Control_Requirements.md"

    if complete and not os.path.isfile(source_doc):
        raise FileNotFoundError(
            f"源需求文档未找到：{source_doc!r}。"
            "请用 --source-doc 指定路径，或用 --no-complete 跳过补全闭环。"
        )

    policy = extract(
        doc_path,
        use_llm=use_llm,
        provider=llm_provider,
        model=llm_model,
    )
    check = self_check(policy)
    if not check.ok:
        raise ValueError(
            f"IR 自检未通过：重复 id={check.duplicate_ids}，恒假规则={check.vacuous_rule_ids}"
        )

    os.makedirs(out_dir, exist_ok=True)

    # Build before report and write report_before.* files
    before = build_report(policy)
    report_paths = _rename_smt_export(
        write_policy_reports(policy, out_dir, "report_before", report=before),
        out_dir,
        "policy_before.smt2",
    )

    completion = None
    final_report_paths = None
    completed_requirements_path = None
    final_ir_path = None

    if complete:
        result = run_completion(policy)
        completion = result
        final_policy = result.final_policy
        after = build_report(final_policy)

        # Write report_after.* files using already-built after report, then overwrite md with comparison
        final_report_paths = _rename_smt_export(
            write_policy_reports(final_policy, out_dir, "report_after", report=after),
            out_dir,
            "policy_after.smt2",
        )
        after_md_path = final_report_paths[0]
        with open(after_md_path, "w", encoding="utf-8") as f:
            f.write(render_markdown(after, label="after", compare=before, completion=result))

        # Write final_ir.yaml (enum values as strings via model_dump mode="json")
        final_ir_path = os.path.join(out_dir, "final_ir.yaml")
        with open(final_ir_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(final_policy.model_dump(mode="json"), f, allow_unicode=True)

        # Read source doc and apply NL patch
        with open(source_doc, encoding="utf-8") as f:
            source_md = f.read()
        patched_text, _ = apply_nl_patch(source_md, result.initial_policy, final_policy)
        completed_requirements_path = os.path.join(out_dir, "completed_requirements.md")
        with open(completed_requirements_path, "w", encoding="utf-8") as f:
            f.write(patched_text)

    return {
        "report_paths": report_paths,
        "final_report_paths": final_report_paths,
        "completion": completion,
        "completed_requirements_path": completed_requirements_path,
        "final_ir_path": final_ir_path,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Agent 访问控制需求完备性检查器（MVP demo）"
    )
    parser.add_argument("--doc", required=True, help="需求文档或离线 IR(.yaml) 路径")
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
    args = parser.parse_args(argv)

    result = run_pipeline(
        doc_path=args.doc,
        out_dir=args.out,
        complete=not args.no_complete,
        use_llm=args.use_llm,
        llm_provider=args.llm_provider,
        llm_model=args.llm_model,
        source_doc=args.source_doc,
    )
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
