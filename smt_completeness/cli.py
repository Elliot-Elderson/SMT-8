import argparse
import os

from .completion import run_completion
from .extractor import extract, self_check
from .report import write_reports


def run_pipeline(
    doc_path: str,
    out_dir: str,
    complete: bool = True,
    use_llm: bool = False,
) -> dict:
    policy = extract(doc_path, use_llm=use_llm)
    check = self_check(policy)
    if not check.ok:
        raise ValueError(
            f"IR 自检未通过：重复 id={check.duplicate_ids}，恒假规则={check.vacuous_rule_ids}"
        )

    report_paths = write_reports(policy, out_dir)

    completion = None
    final_report_paths = None
    if complete:
        completion = run_completion(policy)
        final_out = os.path.join(out_dir, "after_completion")
        final_report_paths = write_reports(completion.final_policy, final_out)

    return {
        "report_paths": report_paths,
        "completion": completion,
        "final_report_paths": final_report_paths,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Agent 访问控制需求完备性检查器（MVP demo）"
    )
    parser.add_argument("--doc", required=True, help="需求文档或离线 IR(.yaml) 路径")
    parser.add_argument("--out", default="out", help="报告输出目录")
    parser.add_argument("--no-complete", action="store_true", help="跳过 LLM 闭环补全")
    parser.add_argument("--use-llm", action="store_true", help="启用真实 LLM 抽取（需 API key）")
    args = parser.parse_args(argv)

    result = run_pipeline(
        doc_path=args.doc,
        out_dir=args.out,
        complete=not args.no_complete,
        use_llm=args.use_llm,
    )
    md, js, smt = result["report_paths"]
    print(f"[报告] Markdown: {md}")
    print(f"[报告] JSON:     {js}")
    print(f"[产物] SMT-LIB:  {smt}")
    if result["completion"] is not None:
        c = result["completion"]
        print(
            f"[补全] 轮数={len(c.rounds)} 收敛={c.converged} "
            f"待人工介入={len(c.manual_review_todos)}"
        )
        if result["final_report_paths"]:
            print(f"[补全后报告] {result['final_report_paths'][0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
