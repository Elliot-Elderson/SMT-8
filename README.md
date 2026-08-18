# Agent 访问控制需求完备性检查器（MVP Demo）

把自然语言访问控制需求文档，经 IR → Z3/SMT-LIB → 完备性分析 → 报告 → LLM 单调补全的自动化流水线，产出可解释的完备性评测。

## 安装

```bash
pip install -r requirements.txt
```

## 运行

见 Task 16（`python -m smt_completeness.cli`）。
