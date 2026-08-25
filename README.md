# Agent 访问控制需求完备性检查器（MVP Demo）

把自然语言访问控制需求文档，经 IR → Z3/SMT-LIB → 完备性分析 → 报告 → LLM 单调补全的自动化流水线，产出可解释的完备性评测。

**完整说明手册（概念、原理、学术出处、报告读法、部署与排错）：**  
[`docs/用户手册-Agent访问控制需求完备性检查器.md`](docs/用户手册-Agent访问控制需求完备性检查器.md)

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

# 从已冻结的抽取 IR 继续分析
python -m smt_completeness.cli --from-ir out/extracted_ir.yaml --out out2 --source-doc Abstract_Access_Control_Requirements.md

# 启用真实 LLM 抽取（OpenAI，需 OPENAI_API_KEY）
python -m smt_completeness.cli --doc Abstract_Access_Control_Requirements.md --out out --use-llm

# 使用 DeepSeek（需 DEEPSEEK_API_KEY；默认模型 deepseek-chat）
python -m smt_completeness.cli --doc Abstract_Access_Control_Requirements.md --out out --use-llm --llm-provider deepseek

# 指定 DeepSeek 模型（例如 reasoner）
python -m smt_completeness.cli --doc Abstract_Access_Control_Requirements.md --out out --use-llm --llm-provider deepseek --llm-model deepseek-reasoner
```

环境变量：
- OpenAI：`OPENAI_API_KEY`
- DeepSeek：`DEEPSEEK_API_KEY`（OpenAI 兼容接口 `https://api.deepseek.com`）
- `--force-complete`：抽取质量警告存在时仍强制运行补全闭环。

产物：
- `out/report_before.md` / `out/report_before.json`：补全前完备性评测报告
- `out/extracted_ir.yaml`：硬闸通过后冻结的抽取 Policy IR，可配合 `--from-ir` 复跑。
- `out/report_after.md` / `out/report_after.json`：补全后评测报告（含补全前后对照）
- `out/policy_before.smt2` / `out/policy_after.smt2`：补全前后判定函数的 SMT-LIB 导出
- `out/final_ir.yaml`：LLM 单调补全后的最终 Policy IR
- `out/completed_requirements.md`：源需求文档 + NL 差量标注
