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

产物：
- `out/report.md` / `out/report.json`：完备性评测报告（三分区体积、C1-C4、威胁覆盖率、缺口清单、显式假设）
- `out/policy.smt2`：判定函数的 SMT-LIB 导出
- `out/after_completion/`：LLM 单调闭环补全后的复评报告
