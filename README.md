# Agent 访问控制需求完备性检查器（MVP Demo）

把自然语言访问控制需求文档，经 IR → Z3/SMT-LIB → 完备性分析 → 报告 → LLM 单调补全的自动化流水线，产出可解释的完备性评测。

## 安装

```bash
pip install -r requirements.txt
```

## 运行

```bash
# demo：离线全流程（抽取用 fixture，无需 API key）
python -m smt_completeness.cli --doc smt_completeness/data/ir_openclaw.yaml --out out

# 只出报告、不跑补全闭环
python -m smt_completeness.cli --doc smt_completeness/data/ir_openclaw.yaml --out out --no-complete

# 启用真实 LLM 抽取（需 OPENAI_API_KEY）
python -m smt_completeness.cli --doc Abstract_Access_Control_Requirements.md --out out --use-llm
```

产物：
- `out/report.md` / `out/report.json`：完备性评测报告（三分区体积、C1-C4、威胁覆盖率、缺口清单、显式假设）
- `out/policy.smt2`：判定函数的 SMT-LIB 导出
- `out/after_completion/`：LLM 单调闭环补全后的复评报告
