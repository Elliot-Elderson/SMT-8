# Agent 访问控制需求完备性检查器 —— 说明手册与实战指南

> 面向从未接触过本项目的读者。读完后应能：说清它解决什么、不解决什么；解释核心概念从哪来、为什么这样设计；独立完成部署、跑通 OpenClaw 需求文档场景、阅读报告、排查故障。
>
> 本文以**仓库里实际代码与一次真实离线跑分为准**，不是抽象设计稿的复述。配套材料：
>
> - 设计（初版）：`docs/superpowers/specs/2026-08-18-smt-completeness-checker-mvp-design.md`
> - 设计（反例驱动补全）：`docs/superpowers/specs/2026-08-24-counterexample-driven-completion-design.md`
> - 调研：`docs/research/01-formal-methods-survey.md`、`02-toolchain-selection.md`、`03-threat-baseline.md`
> - 输入样例：`Abstract_Access_Control_Requirements.md`
> - 代码包：`smt_completeness/`

---

## 0. 十分钟速览

把一份**自然语言写的 Agent 访问控制需求**，变成一份**可解释的完备性评测**，并可选地**单调收紧**未表态区（unspecified）。

```
需求文档（或离线 YAML IR）
        │
        ▼
   受控词表 IR（Policy / Rule）
        │
        ├── 自动自检（id 唯一、规则非恒假）
        ├── Python 判定函数 D(s) ∈ {Allow=0, Challenge=1, Deny=2}
        ├── Z3 + BDD 编码 + 导出 policy_before.smt2
        ├── 五项内部分析（一致、冗余、未表态三分区、H1、敏感度偏序）
        ▼
   report_before.md / report_before.json / policy_before.smt2
        │  （可选闭环 --complete，默认开启）
        ▼
   run_completion：反例驱动三阶段
     hygiene → 倒挂对齐 → 未表态显式化
   验证 ∀s D'(s) ≥ D(s)（Z3 单调性门控）
        ▼
   report_after.md（含补全前后对照）/ report_after.json / policy_after.smt2
   final_ir.yaml（最终 Policy IR）
   completed_requirements.md（源文档 + NL 差量标注）
```

**你拿到的不是「证明绝对最安全」**，而是一组**可复算的指标 + 反例 + 两类缺口**（补规则能修 vs 当前词表根本表达不了）。

**定位**：策略**初始化**时用一次的形式化审计工具，不是每次改文档都跑的 CI。可用资产通常只有需求文档本身，**不做「文档 ↔ 实现代码」一致性验证**。

**最快上手（无需 API key）**：

```powershell
Set-Location D:\project\SMT
python -m pip install -r requirements.txt
$env:PYTHONPATH = "D:\project\SMT"
python -m pytest tests -q
python -m smt_completeness.cli --doc smt_completeness/data/ir_openclaw.yaml --out out --no-complete
```

然后打开 `out/report_before.md`。全流程含补全时去掉 `--no-complete`，大约一两分钟。

---

# 第一部分　项目介绍

## 1.1 它要回答的三个问题

安全需求文档（本仓库样例是 OpenClaw）通常会写：

1. 保护什么（凭据、系统敏感文件、Agent 记忆……）
2. 什么必须拒绝、什么必须再问一次、什么可以放行
3. 用哪些**可观察特征**识别这些情况

人读完仍难回答：

| 问题 | 日常说法 | 本工具的量化回答 |
| --- | --- | --- |
| 规则自己打架吗？ | 同一行为既禁止又要求「再判断」 | C3：mandatory_deny ∩ must_challenge 的状态数与反例 |
| 有没有写了等于没写的规则？ | 删掉某条，策略完全不变 | C4：贪心固化后的冗余 id |
| 还有没有未显式表态的区域？ | 没写规则时默认 Allow 或默认 Challenge | C2：`V_unspecified`（`v_unspecified_allow` + `v_unspecified_challenge`）+ 可读 cube |
| 还能不能把某条规则再收紧一级？ | 过度授权 | C1 / H1：可收紧规则列表 |
| 高敏感资源会不会比低敏感更宽松？ | 文档 §2.3 自己承认的不对称 | 敏感度单调性 |

## 1.2 它不是什么

- **不是**运行时拦截器（不挂钩真实工具调用）。
- **不是**「文档已经实现了」的证明（没有策略图、没有日志、没有 golden case）。
- **不是**绝对最紧证明。H1 只搜索「把某条规则结论上调一级」，不搜索重写条件、新增切割维度。
- **不是**把 120 条威胁库全跑完的产品；威胁基线（`threats/baseline.py`）是可选保留模块，报告主路径不再强制输出外部威胁对照节。
- Demo **没有人工审核 UI**：抽取默认 `auto_approved`；补全门控基于 Z3 单调性验证，无法通过则跳过。

## 1.3 在完整系统里的位置

设计文档规定：用于**完整系统的策略初始化**——把自然语言需求变成可验证的初始策略，并指出缺口。修改需求文档后**不必**自动重跑；需要时再手动跑一次。

## 1.4 输入与输出

**输入（二选一）**

| 输入 | 何时用 | 命令要点 |
| --- | --- | --- |
| 离线 IR YAML | 默认 demo，可复现、无需密钥 | `--doc smt_completeness/data/ir_openclaw.yaml` |
| 自然语言 Markdown | 真抽取 | `--use-llm`，并设 `OPENAI_API_KEY` 或 `DEEPSEEK_API_KEY` |

OpenClaw 原文：`Abstract_Access_Control_Requirements.md`。离线 fixture 是把它 §3/§4/§5 折叠进受控词表后的 **24 条规则**。

**输出（一次运行）**

| 文件 | 作用 |
| --- | --- |
| `out/report_before.md` | 给人读的补全前评测报告 |
| `out/report_before.json` | 给脚本/二次分析的结构化数字（无 baseline 字段） |
| `out/policy_before.smt2` | 补全前判定函数的 SMT-LIB |
| `out/report_after.md` | 补全后报告，含前后对照表（未加 `--no-complete`） |
| `out/report_after.json` | 补全后结构化数字 |
| `out/policy_after.smt2` | 补全后判定函数的 SMT-LIB |
| `out/final_ir.yaml` | 最终 Policy IR（YAML） |
| `out/completed_requirements.md` | 源文档 + NL 差量标注（必须拒绝 / 进一步判断补全追加） |

## 1.5 代码结构（按数据流）

```
smt_completeness/
  vocab.py              受控词表：操作/资源/区域/判定等级/风险与污点 flag/敏感度秩
  state_space.py        State + 合法状态枚举（122880）
  ir.py                 Condition / Rule / Policy（pydantic 校验）
  extractor.py          加载 YAML 或 LLM 抽取 + self_check
  llm_client.py         OpenAI / DeepSeek（OpenAI 兼容接口）
  compiler.py           decide_py、MustAllow、Z3Env、导出 .smt2
  analysis/
    consistency.py      C3
    redundancy.py       C4
    coverage.py         C2 三分区 + cube 泛化
    tightening.py       C1 H1
    monotonicity.py     敏感度偏序 + 同级不对称
  threats/baseline.py   外部不变量逐条检验
  report.py             汇总 Markdown/JSON + 调 SMT 导出
  completion.py         卫生 → 倒挂对齐 → 未表态 Challenge → 单调验证
  cli.py                命令行入口
  data/
    ir_openclaw.yaml    离线 IR
    threat_seed.yaml    18 条威胁不变量
tests/                  pytest，testpaths=tests（见 pytest.ini）
```

入口函数：`smt_completeness.cli.run_pipeline`：

1. `extract` → `Policy`
2. `self_check`，失败则 `ValueError`
3. `build_report(policy)` → 写 `report_before.*` + `policy_before.smt2`
4. 若 `complete=True`：`run_completion` → `build_report(final)` → 写 `report_after.*`（md 含对照）、`policy_after.smt2`、`final_ir.yaml`；读源文档 → `apply_nl_patch` → `completed_requirements.md`

## 1.6 技术栈：为什么是这些组件

| 组件 | 版本约束 | 为什么选它 | 为什么不选常见替代 |
| --- | --- | --- | --- |
| Python 3.10+ | 项目用 `str \| None` 等语法 | 全仓库一种语言，Windows 零编译 | — |
| `z3-solver` | ≥4.13 | 工业 SMT 标准；SAT/UNSAT 查询、反例与 witness 可导出 SMT-LIB | Z3 不负责模型计数；计数交给 BDD（`dd`） |
| `pydantic` ≥2.8 | 随 instructor | IR 与 LLM 输出同一 schema | 纯 prompt 无法强制封闭词表 |
| `instructor` ≥1.0 | 结构化抽取 | 校验失败自动带错重试 | 手写 JSON 解析易漂 |
| `dd` | ≥0.6 | one-hot BDD 精确计数 Valid / explicit / unspecified | 生产分析不跑 Python `all_states()` 全枚举 |
| `pyyaml` | IR/种子表 | 人可审阅 | JSON 对中文溯源不够友好 |

**Z3 编码约定（踩过的坑，写进设计 §8.3）**

- 判定用 **Int 0/1/2**，不用 `z3.Datatype`：「更严格」就是数值更大。
- 枚举维度用 `EnumSort`；判定用嵌套 `If`，查询落在无量词有限域。
- 每个 `Z3Env` 给 sort 加唯一前缀 `smtc_N_`，避免多次建环境时符号冲突。
- 分母是**合法状态数** `6×10×4×2⁹ = 122880`，由 BDD `count(Valid)` 得到，不是二进制码点 2ⁿ，也不是 Python 枚举循环。

---

# 第二部分　原理：概念、设计理由与学术出处

读这一部分时，请始终记住：**完备性在访问控制文献里很少直接叫 completeness**（该词常被 SMT「完全性」占用）。本项目把「够不够安全」拆成一组**可判定、可计数、可给反例**的算子。

## 2.1 总设计思路：神经符号，而不是「让 LLM 当裁判」

流水线是 **LLM（或离线 fixture）提议结构，Z3 与 BDD 持有安全逻辑**。这与 AutoCedar 的纪律一致：模型只提候选，验证器裁决。

Demo 里补全不让 LLM 当裁判：三条路径依次处理卫生问题、敏感度倒挂对齐、未表态区域的 Challenge 显式化；未表态不会被默认升成 Deny。`render_chinese` 只是中文模板，当前报告主路径甚至不调用它。`--use-llm` 只作用在**抽取**阶段。

## 2.2 需求文档如何映射成形式对象

OpenClaw 文档本身就是一份「上界 + 中间层 + 下界 + 执行语义」：

| 文档章节 | 形式化角色 | 代码对应 |
| --- | --- | --- |
| §2 受保护对象 | `resource_class` 取值定义 | `vocab.ResourceClass` |
| §3 必须拒绝 | 强制上界 ceiling | `RuleKind.MANDATORY_DENY` |
| §4 必须进一步判断 | 不可降为 Allow 的中间层 | `RuleKind.MUST_CHALLENGE` |
| §5 可保留工作流 | 可用性下界 floor | `RuleKind.MAY_ALLOW`，再经 MustAllow 公式削减 |
| §6.1 行为归一化 | 可观察维度词汇表 V | `operation` / `resource_class` / `target_zone` / flags |
| §6.3 策略选择顺序 | 判定函数消解 | `decide_py` |
| §5 结尾限定语 | floor 必须减去 §3、§4 | `must_allow` |
| §9 实现限制 | 长期策略看不到写入内容等 | 报告里的 `V_unspecified_challenge` + 词表缺失 |

**为什么这样切**：与 IFCIL（CSF 2022 / ACM TOPS）把需求分成 **functional requirements（必须能完成的任务）** 与 **security requirements（必须挡住的流）** 是同一结构；也与 AutoCedar 的 floor / ceiling 一致。没有下界，分析会把「全 Deny」当成最安全——那在工程上不可用。

## 2.3 受控词表（Vocabulary）

**定义**：IR 与 LLM 允许出现的符号的封闭集合。不在表内的字符串，pydantic 直接拒绝。

**为什么封闭**：自动形式化的第一失败模式是模型发明「新操作名」。Instructor 把 Enum/Literal 编进 JSON Schema，服务端强制封闭（设计文档复用 `02-toolchain-selection.md` H 节）。

当前切片（`vocab.py`）：

| 维度 | 取值 | 设计理由 |
| --- | --- | --- |
| `Operation` | read, write, send, execute, delete, list | 文档 §6.1 列出十种操作；demo 取六种覆盖 §3–§5 主路径。打包/权限变更/调度/注册未单列，属于范围裁剪 |
| `ResourceClass` | 10 类（凭据…未知） | 对齐文档 §2 |
| `TargetZone` | local, internal, external, unknown | 对齐 §2.7；未知与外部在外发规则中同等对待 |
| 风险 flag | 6 位（削弱控制、持久化、提权、供应链执行、破坏、侦察扫描） | 把 §3 里「命令形态」折叠成布尔，避免字符串/正则层 |
| 污点 flag | 3 位（凭据/私人数据/session） | 文档 §6.2 数据流继承；阶段一当**自由输入位**，不做 K 步时序 |
| `Decision` | Allow=0 ≺ Challenge=1 ≺ Deny=2 | 三值：AgentSpec 把「要求用户确认」做成 enforcement；文档 §4 的「进一步判断」就是 Challenge |

**显式假设 A1**：不引入 `tool` 维度——当前文档规则不依赖工具名。  
**显式假设 A2**：资源分类器完美——路径变形（`../.ssh`）在原型不可见。

敏感度秩（越大越敏感）：凭据 7 ≻ 系统敏感 6 ≻ **私有上下文 = 记忆 5** ≻ 私人数据 4 ≻ 配置 3 ≻ 源码 2 ≻ 普通文件 1。`external_service` / `unknown` 不参与偏序。同级设定来自文档 §2.3：「强制拒绝直接保护的是 Agent 私有上下文读取」，记忆是另一类。

## 2.4 状态与状态空间

**定义**：一个**抽象请求** `State = (operation, resource_class, target_zone, flags)`。

**规模**：

\[
|S| = 6 \times 10 \times 4 \times 2^{9} = 122880
\]

代码常量：`EXPECTED_STATE_COUNT`。测试断言 `EXPECTED_STATE_COUNT == 122880`；`BDDEnv` 会在 `count(Valid)` 不匹配时抛错。

**为什么 BDD 计数 + Z3 反例**：Quacky（ICSE 2022）用 SMT + 模型计数器量化 IAM 策略「有多宽松」。本 demo 状态空间在 10⁵ / 122880 量级，计数用 BDD，有无性与反例用 Z3；`all_states()` 仅保留为调试辅助，生产分析与补全禁止穷举。

**立方体（cube）**：若干维取具体值、其余 don’t-care 的状态集合。条件里「缺省维度 = 通配」。未表态立方体会先泛化成少量 cube，再交给补全；泛化时限制 `k≤3`，并丢弃与当前解释无关的 flag。出处：防火墙分析里用 BDD 表示谓词集合（FIREMAN, S&P 2006）；Margrave（LISA 2010）强调**穷尽具体场景**比单反例更适于给人看。

## 2.5 中间表示 IR

一条规则（`ir.py`）的关键字段：

| 字段 | 含义 |
| --- | --- |
| `id` | 稳定标识，如 `R3.1.1` |
| `source_anchor` | 溯源到文档小节 |
| `kind` | mandatory_deny / must_challenge / may_allow（另有 resource_def、limitation 占位） |
| `condition` | 各维列表；空 = 通配；`flag_true` / `flag_false` 必须 ∈ `ALL_FLAGS` |
| `decision` | 0/1/2，且与 kind **强制一致**（model_validator） |
| `priority` | mandatory / learned / default |
| `reviewer_status` | demo 默认 `auto_approved` |
| `provenance` | extracted 或 llm_synthesized |

**自检 `self_check`**：id 唯一；每条规则在合法状态空间上至少命中一次（非 vacuity）。Vacuity 作为准入门槛来自 Cedar/AutoCedar 的 match-vacuity 检查思想；本实现用 Z3 `is_vacuous`，不是枚举。

离线模式若 `--doc` 不是 `.yaml/.yml`，会 **ValueError**，避免把 Markdown 静默换成 fixture。

## 2.6 判定函数 D（核心语义）

文档 §6.3：拒绝优先于进一步判断，进一步判断优先于允许；无完整匹配时，无风险的本地读/列举可默认允许，其余进 LLM 兜底。代码一字不差地实现为：

```
若命中任一 mandatory_deny     → Deny
否则若命中任一 must_challenge → Challenge
否则若命中任一 may_allow      → Allow
否则若 无 flag ∧ op∈{read,list} ∧ zone=local → Allow   （默认允许）
否则 → Challenge                                          （默认甩给 LLM）
```

因为有默认兜底，**不存在 Undefined**。所以「盲区」不是「没定义」，而是：

- 无规则且落入**默认 Allow** → `V_unspecified_allow`
- 无规则且落入**默认 Challenge** → `V_unspecified_challenge`

**学术对照**：SELinux `neverallow` 压倒 `allow`、Cedar deny-overrides、AWS explicit deny，都是同一优先序。Zelkova（FMCAD 2018）把「对所有 request context 做 SMT 推理」对照「逐请求模拟」；本项目的 D 是同一思想在三值、有限抽象上的实现。

## 2.7 MustAllow（可用性下界）

**定义**（代码 `must_allow`）：

\[
\mathrm{MustAllow}(s) \equiv \text{命中 §5} \land \neg\text{命中 §3} \land \neg\text{命中 §4}
\]

**为什么不能直接用 §5**：文档写明「只要同一操作还携带更高风险特征，就必须优先执行第 3 或第 4 节」。划宽了，H1 会假性 tight；划窄了，会报大量「误杀正常工作流」的假缺口。这是 **A3**，也是可收紧性结论的强度上限。

**术语出处**：

- *must-allow request set*：Quantitative Policy Repair（ISSTA 2023）
- functional requirements：IFCIL（CSF 2022）
- floor / liveness slice：AutoCedar（arXiv:2607.03656）

## 2.8 五项内部分析

设计文写「每项 Python + Z3 对账」。当前生产路径使用 Z3 给 witness / 反例、BDD 给计数；Python `all_states()` 只作为调试辅助，不作为分析与补全主路径。

### C3 一致性

**定义**：效果优先级是设计不是缺陷。真正要报的是 **同为 mandatory 但效果不同且共同命中**。Demo 检测 `mandatory_deny ∩ must_challenge`：Challenge 被 Deny 掩盖。

- BDD：计数两边共同命中的状态体积。
- Z3：`SAT(deny_expr ∧ chal_expr)`，`find_witness`。
- 断言：`count>0` 当且仅当 Z3 有模型。
- JSON 里的 `deny_rule_ids` / `challenge_rule_ids` 是**命中该反例状态的规则**，不是该 kind 下全部规则。

OpenClaw 离线 IR 上重叠约 **5052** 个状态（例如写 config 且带 `weakens_control`：§4 的 config 写入 Challenge 被 §3 的削弱控制 Deny 盖住）。这通常表示**消解语义在工作**，阅读时不要直接当成「文档写错了」。

**出处**：FIREMAN 的 inconsistency / shadowing；Margrave 的 overlap 与 rule responsibility。

### C4 无冗余

**定义**：删掉规则 r 后，对所有 s，`D` 不变，则 r 冗余。

**陷阱（必须避开）**：两条互为备份，单独删都「冗余」，一起删就不冗余。所以 **贪心 + 固化**：试删一条 → 全空间等价才真删 → 再试下一条。不能先标记再批量删。

**出处**：FIREMAN inefficiency；Cedar Analysis 的 redundancy。

离线 IR 上贪心会标出 `R4.1/R4.2/R4.3`：它们覆盖的区域已被更严的 Deny 完全盖住，对 D 无贡献。这与 C3 重叠、H1「§4 可收紧」是同一现象的三种视图。

### C2 三分区（无盲区的操作化）

对每个状态：

- 任一条 deny/challenge/allow 命中 → 计入 `V_explicit`
- 否则若 `is_default_allow` → `V_unspecified_allow`
- 否则 → `V_unspecified_challenge`

三者之和必须等于 122880。

离线 IR 一次实测量级（补全前）：

| 指标 | 约数 | 读法 |
| --- | --- | --- |
| V_explicit | 121428（98.82%） | 长期规则已经说话 |
| V_unspecified_allow | 8（0.01%） | 无显式规则但默认 Allow，应优先显式化 |
| V_unspecified_challenge | 1444（1.18%） | 无显式规则但默认 Challenge；量化文档 §9「长期策略表达不了内容级授权」 |

补全后典型变化：规则 24→32，**V_unspecified_allow → 0**，`V_unspecified_challenge` 仍约 1444。说明：闭环把默认 Allow 显式化，并对未表态默认 Challenge 保持 Challenge；不会把未表态区域默认升成 Deny。

**定量覆盖的文献**：Quacky 的 permissiveness 是 `#允许 / #宇宙`。这里把宇宙切成三块，语义比单一许可度更贴 Agent（有 Challenge 层）。

### C1 可收紧性 H1

**定义**：对结论尚未到 Deny 的规则 r，把结论上调一级得到 D_r↑（**同时改 kind**，因为 `decide_py` 只看 kind）。若没有任何 MustAllow 状态从 Allow 变成非 Allow，则 r **可收紧**。

- `is_h1_tight == True` 表示：在「只上调结论一级」的搜索空间里不能再收紧。
- **不是**绝对最紧。重写条件、加维度、加新规则都不在 H1 内（A4）。

**出处与教训**：IAM-PolicyRefiner（OOPSLA 2024，PACMPL 8(OOPSLA2) Article 298，Def. 4.1 **Tightness**）。不加语法/搜索空间限制时，tightness **平凡为假**（总能收到「恰好 MustAllow」）。本项目故意取**最弱语法偏置 H1**。

文献上 Tightness 多当作**合成目标**；本项目把它当作**对既有需求集的验证性质并给出证书（可收紧 id 或证人）**——调研 §3 将其标为可能新颖点。

OpenClaw 上 `R4.*` 常进入可收紧列表：MustAllow 已排除 challenge 命中，把 Challenge 升到 Deny 打不破 floor。正确但易误读成「§4 写得太松」；更准确的读法是「相对 MustAllow，§4 不是可用性所必需」。

### 敏感度单调性

**严格倒挂**：仅资源类别不同，高敏感却得到更宽松的 D。  
**同级不对称**：秩相同、类别不同、D 不同。

实现按 `(operation, zone, flags)` 去重后比较各类别，避免把同一上下文重复计数约 10 倍。

OpenClaw **必现亮点**：读 `agent_memory` 可为 Allow(0)，同条件下读 `agent_private_context` 为 Deny(2)。这是文档 §2.3 自己写明的不对称，工具把它变成机器可算的例子（A5：偏序来自章节组织，输出需人复核）。

## 2.9 外部威胁基线

**定义**：每条不变量形如「凡满足 Pre 的状态，D 不得低于 min_decision」（1=Challenge，2=Deny）。

检验：`SAT(Pre ∧ D < min)` 由 Z3 给 witness；相关体积由 BDD 计数。

- `expressible: false` → **词表缺失**（不是少写一条规则）
- 可表达但有反例 → **需求缺失**
- 否则 → 已覆盖

Demo 18 条，溯源 ATT&CK / ATLAS 等，映射到本词表。完整 120 条种子在 `docs/research/03-threat-baseline.md`。

离线 IR 补全前约 **12/18 = 66.67%**；补全后约 **13/18**（记忆读取被显式化后，TINV-PRIV-READ-MEM 可变为覆盖）。**TINV-CRED-18 凭据写入**仍是需求缺失：它落在 `V_unspecified_challenge`，不会被默认升成 Deny。

**三类必看缺口**

| ID | 类型 | 含义 |
| --- | --- | --- |
| TINV-CRED-18 | 需求缺失 | 写凭据/authorized_keys 应 Deny；文档侧重读 |
| TINV-EXFIL-07 | 词表缺失 | AML.T0077 模型输出渲染外泄，没有「输出内容」维度 |
| TINV-CRED-05 | 词表缺失 | docker.sock 未列入系统敏感 |

**出处**：OWASP ASI、MITRE ATLAS/ATT&CK、SAFE-MCP；把威胁写成可机器检查的不变量，是本 demo 相对「纯内部分析」的增量。

## 2.10 单调闭环补全

每轮：

1. 卫生补全：修正自检、恒假、结构性缺口
2. 倒挂对齐：在敏感度偏序上消除可证明的更宽松高敏感状态
3. 未表态显式化：把默认 Allow / 默认 Challenge 的区域写成显式规则，其中未表态默认保持 Challenge，不默认 Deny
4. `verify_monotone`：∀s D_new(s) ≥ D_old(s)（对应文档 §8「历史拒绝不得变允许」）
5. 不单调 → 停止，写 `manual_review_todos`
6. 否则合入，最多 5 轮

终止性：三元链上严格改善有限。安全逻辑在分析器，不在 LLM。

**出处**：AutoCedar 反例三分类回传；CEGIS 风格「反例 → 候选 → 验证」；本 demo 不做真 ∃∀ CEGIS（设计已砍 H2/QBF）。

## 2.11 学术谱系：解决了什么、创新在哪

### 本项目站在哪条线上

```
防火墙/XACML 静态分析（FIREMAN, Margrave, XACML-SMT）
        → 云 IAM 的 SMT（Zelkova / IAM Access Analyzer）
        → 定量许可度（Quacky）与收紧合成（IAM-PolicyRefiner, Cedar Restricter）
        → 自然语言→策略（AutoCedar）
        ×
Agent 运行时防护（AgentSpec, Progent, CaMeL）——通常不做「需求文档静态完备性」
```

设计文档的落点：**填上「静态策略分析（二值、单请求、无 Agent）」与「Agent 运行时防护（有 Challenge，无静态完备性）」之间的空白**——对 Agent 工具调用需求做**三值静态完备性评估**，并对照公开威胁库回答「还缺哪些方面」。

### 直接复用（不要当成本项目原创）

| 工作 | 出处 | 复用了什么 |
| --- | --- | --- |
| Zelkova | Backes et al., FMCAD 2018, DOI 10.23919/FMCAD.2018.8602994 | SMT 对全请求空间推理；性质与策略同构 |
| FIREMAN | Yuan et al., IEEE S&P 2006, DOI 10.1109/SP.2006.16 | 一致性 / 冗余的操作化；有限状态 ⇒ 可判定 |
| Margrave | Nelson et al., LISA 2010 | 不要求用户另写规格；穷尽场景 |
| Cedar | Cutler et al., OOPSLA 2024, DOI 10.1145/3649835 | 为可分析性设计语言；vacuity/冗余 API 的思想 |
| IAM-PolicyRefiner | D’Antoni et al., OOPSLA 2024, PACMPL 8(OOPSLA2):298 | Tightness；无搜索空间则平凡假 |
| Quacky | Eiers et al., ICSE 2022 Companion, DOI 10.1145/3551349.3559530 | 许可度量化；本项目用 BDD 计数而非生产穷举 |
| Quantitative Policy Repair | Eiers et al., ISSTA 2023 | must-allow request set |
| AutoCedar | arXiv:2607.03656 | 抽取+溯源；LLM 不持裁决权；反例分类 |
| AgentSpec | Wang et al., arXiv:2503.18666（ICSE 2026） | trigger+predicate+enforcement；用户确认 ≈ Challenge |
| IFCIL | Ceragioli et al., CSF 2022 / ACM TOPS | functional vs security 双侧约束 |
| HRU | Harrison, Ruzzo, Ullman, 1976 | 含管理性命令时安全性不可判定 → **A7** 划界 |
| Instructor | 工业库 | 结构化输出 + 校验重试 |

威胁编号示例：ATT&CK T1098.004（SSH Authorized Keys）、T1552.*（凭据文件）、ATLAS AML.T0077（LLM Response Rendering）。

### 本 demo 相对文献的增量（如实说）

1. **对象**：不是 AWS IAM / Cedar 授权策略，而是 **Agent 工具调用安全需求文档**（三值 + 污点位 + Challenge 默认）。
2. **完备性操作化**：内部四项（一致、冗余、三分区、H1）+ 敏感度偏序 + **外部威胁不变量**，并区分 **需求缺失 vs 词表缺失**。
3. **H1 作为验证而非合成**：给出「相对规则级收紧空间是否 tight」的证书。
4. **初始化场景**：只有文档、没有访问日志（PolicyRefiner 依赖日志，本项目没有）。
5. **工程裁剪**：无 CEGIS/QBF、无字符串层、污点非时序、威胁种子 18 条。数学严谨度服从可跑通的原型。

不要对外宣称「已证明找不到任何更安全的需求」——那是被砍掉的 H2。正确口径见报告第 4 节与 A4。

## 2.12 显式假设 A1–A7（读报告第 7 节时对照）

| # | 内容 | 若违反会怎样 |
| --- | --- | --- |
| A1 | 无 tool 维 | 依赖具体工具名的规则无法表达 |
| A2 | 分类器完美 | 路径绕过不可见 |
| A3 | MustAllow 推导正确 | H1 假阳/假阴 |
| A4 | H1 ≠ 绝对紧 | 过度宣称 |
| A5 | 敏感度来自章节序 | 假倒挂 |
| A6 | 种子表质量 | 覆盖率不可信 |
| A7 | 无角色委派等管理语义 | 否则落入 HRU 不可判定区 |

---

# 第三部分　如何阅读产出

## 3.1 三种文件怎么配合

先读 **Markdown** 建立图景，用 **JSON** 做断言或画图，用 **SMT-LIB** 在 Z3 里独立检查判定函数是否可解析。三者由同一次 `build_report` 生成，数字应一致。

## 3.2 `report_before.md` / `report_after.md` 逐节

### §1 概览

- 规则总数：IR 条数（离线 24；补全后可到 32）。
- 自动自检：必须通过，否则 CLI 根本不会写报告。

### §2 三分区体积（C2）——最先看

关注 **V_unspecified**（`v_unspecified_allow` + `v_unspecified_challenge`）。其中 `v_unspecified_allow` 非零表示存在「没规则、系统自动放行」的默认 Allow 盲区。其下 cube：

- 空列表打印为 `*`（通配）
- `flag_true` / `flag_false` 是必须真/必须假
- `dc=` 才是 don't-care 的 flag（两列表都未出现的）

早期 `_demo_out/report.md` 曾把 `flag_false` 误标成 don't-care，**当前代码已改正**。请以新跑的 `out/report_before.md` 为准。

### §3 一致性与冗余

- 重叠数大：先看示例状态，判断是「Deny 盖住 Challenge」（常为预期）还是真矛盾。
- 冗余 id：删了对 D 无影响；可能仍有文档/教学价值。

### §4 H1

- `is_h1_tight: false` + `R4.*` 可收紧：结合 MustAllow 理解，不要直接改文档把 §4 全改成 Deny。
- 若将来所有规则都不可上调：只能说「相对 H1 已 tight」。

### §5 敏感度

倒挂/不对称的「高 / 低」是两个只差 `resource_class` 的状态。`D=` 为 0/1/2。优先看 memory vs private_context。

### §6 补全前后对照（仅 report_after.md）

出现于 `report_after.md`，标题为「补全前后对照」。可看倒挂数、V_unspecified、规则数等指标的 before→after 变化。外部威胁基线对照不再作为必出节；`threats/baseline.py` 保留为可选模块，可独立调用。
## 3.3 `report.json` 字段地图

顶层：`self_check`、`consistency`、`redundancy`、`coverage`、`tightening`、`monotonicity`、`assumptions`。
（无 `baseline` 字段；威胁基线不再作为必出节。）

常用：

- `coverage.v_unspecified`、`coverage.v_unspecified_allow`、`coverage.unspecified_cubes`
- `consistency.overlap_count`、`example_state`、`deny_rule_ids`
- `tightening.tightenable_rule_ids`、`is_h1_tight`
- `monotonicity.inversion_count`、`equal_rank_asymmetry_count`

脚本示例：比较补全前后 `coverage.v_unspecified` 应 `after <= before`（e2e 测试即如此）。

## 3.4 `policy_before.smt2` / `policy_after.smt2`

UTF-8 文本，含 `Allow=0, Challenge=1, Deny=2` 注释。用 Z3 打开应能解析。它编码的是**当前 Policy 的 D**，不是自然语言全文。

## 3.5 补全前后对照（OpenClaw 离线，一次真实运行）

| 项 | 补全前 | 补全后 |
| --- | --- | --- |
| 规则数 | 24 | 32 |
| V_unspecified_allow | 8 | 0 |
| V_unspecified_challenge | 1444 | 1444 |
| 倒挂数 | >0 | 减少 |
| 同级不对称 | 64 | 62（记忆读被部分收紧） |

**阅读结论示例（可作汇报口径）**：

1. 默认 Allow 面极小且可被单调补全关掉。
2. 主要残余风险在 **Challenge 依赖** 与 **词表天花板**，不是「再写几条默认拒绝」能单独解决。
3. 凭据**写入**、模型输出渲染外泄、docker.sock 是文档级/词表级问题，与 §9 自述一致。

---

# 第四部分　部署、实战与排错

## 4.1 环境要求

- Windows / Linux / macOS，**Python 3.10+**（开发机验证过 3.14）。
- 内存普通笔记本即可；一次全量分析大约 **1–3 分钟**（含补全与多项 BDD/Z3 分析）。
- 离线路径**不需要**网络和 API key。
- PowerShell 不要用 bash 的 `&&`；用 `;`。建议：

```powershell
Set-Location <仓库根目录>
$env:PYTHONPATH = (Get-Location).Path
```

控制台中文可能乱码（代码页），**文件是 UTF-8**，请用编辑器打开 `report_before.md`；若跑了补全流程，再打开 `report_after.md`。

## 4.2 安装

```powershell
python -m pip install -r requirements.txt
```

依赖：`z3-solver`、`instructor`、`pydantic`、`pyyaml`、`pytest`。`openai` 由 instructor 拉取，`--use-llm` 需要它。

验证：

```powershell
python -c "import z3; print(z3.get_version_string())"
python -m pytest tests -q
```

预期：**约 50 passed**（随测试增减以实际输出为准），耗时约 2–3 分钟。`pytest.ini` 已设 `testpaths = tests`，根目录 `_*.py` 垃圾文件不会被收集。

## 4.3 CLI

```text
python -m smt_completeness.cli --doc PATH --out DIR
    [--no-complete] [--use-llm]
    [--llm-provider openai|deepseek] [--llm-model NAME]
```

| 参数 | 含义 |
| --- | --- |
| `--doc` | YAML IR，或 `--use-llm` 时的 Markdown |
| `--out` | 输出目录，默认 `out`（已 gitignore） |
| `--no-complete` | 只报告，不跑补全闭环 |
| `--use-llm` | instructor 抽取 |
| `--llm-provider` | `openai`（默认，`OPENAI_API_KEY`）或 `deepseek`（`DEEPSEEK_API_KEY`，`https://api.deepseek.com`） |
| `--llm-model` | 覆盖默认：`gpt-4o` / `deepseek-chat`；DeepSeek 推理可用 `deepseek-reasoner` |
| `--source-doc` | 源需求文档路径（默认 `Abstract_Access_Control_Requirements.md`），用于 NL 补丁输出 |
| `--polish-nl` | 保留选项，当前忽略 |

成功时 stdout：

```text
[报告] Markdown: ...
[报告] JSON:     ...
[产物] SMT-LIB:  ...
[补全] 轮数=... 收敛=... 人工复核项=...
[补全后报告] ...
```

## 4.4 典型场景 A：用安全需求文档做全流程验收（推荐主路径）

目标：证明解析器在 **OpenClaw 需求**上完整可用。分三档，由浅入深。

### A0. 单元/集成测试（机器验收）

```powershell
python -m pytest tests -q
```

失败则先不要解读业务报告。覆盖：词表、状态数、IR 校验、编译器、抽取自检、C1–C4、单调性、威胁、报告、补全、CLI e2e、LLM provider 配置（不打真实网）。

### A1. 离线报告（无密钥，可复现）

```powershell
python -m smt_completeness.cli --doc smt_completeness/data/ir_openclaw.yaml --out out --no-complete
```

**验收清单**

- [ ] 生成 `out/report_before.md`、`out/report_before.json`、`out/policy_before.smt2`
- [ ] 概览规则数 = 24，自检通过
- [ ] `coverage.total == 122880`，v_explicit + v_unspecified = total
- [ ] 报告含 A1–A8
- [ ] §5 能看到 agent_memory vs agent_private_context
- [ ] 报告 JSON 无 `baseline` 字段

对照原文：`Abstract_Access_Control_Requirements.md` §3.1 禁读凭据、§2.3 记忆与上下文分离、§9 内容级授权未入长期策略。

### A2. 离线全流程（含补全）

```powershell
python -m smt_completeness.cli --doc smt_completeness/data/ir_openclaw.yaml --out out
```

**验收清单**

- [ ] 另有 `out/report_after.md`（及 json/smt2）、`out/final_ir.yaml`、`out/completed_requirements.md`
- [ ] `report_after.md` 含「补全前后对照」节
- [ ] 补全后 `v_unspecified_allow` ≤ 补全前（常见 8 → 0）
- [ ] `completed_requirements.md` 含「必须拒绝」补全追加内容

### A3. 从自然语言抽取（可选，需密钥）

OpenAI：

```powershell
$env:OPENAI_API_KEY = "sk-..."
python -m smt_completeness.cli --doc Abstract_Access_Control_Requirements.md --out out-llm --use-llm --no-complete
```

DeepSeek：

```powershell
$env:DEEPSEEK_API_KEY = "sk-..."
python -m smt_completeness.cli --doc Abstract_Access_Control_Requirements.md --out out-ds --use-llm --llm-provider deepseek --no-complete
```

**预期与注意**

- 抽取结果**不必**等于 24 条 fixture；词表封闭，非法 flag 会重试最多 3 次。`out-ds/` 不是金标准——DeepSeek 与 OpenAI 对同一文档的抽取可能相差数条规则，需人工复核。
- 先 `--no-complete` 检查自检与规则是否离谱，再决定是否补全。
- 费用与稳定性取决于模型；失败见 4.8。
- 不要把 Markdown 路径在**不带** `--use-llm` 时传入——会报错（故意的）。

## 4.5 典型场景 B：只审计、不改策略

与 A1 相同，加 `--no-complete`。适合初始化评审会：只展示缺口，不自动合入新 Deny。

## 4.6 典型场景 C：解释「还缺哪些方面」

先看本次运行的主报告：`report_before.md` 给出补全前的缺口，`report_after.md`（未加 `--no-complete` 时生成）在 §6「补全前后对照」汇总指标变化。

1. 对照 `report_before.md` / `report_after.md` 的 V_unspecified、倒挂数、规则数，说明补全实际关闭了哪些默认 Allow 或敏感度倒挂。
2. 需求缺失 → 能否在现有四维上加规则（凭据 write、bash history 映射到 config 读等，后者是近似）。
3. 词表缺失 → 列入下一阶段观察维度 backlog，而不是催更多 YAML 规则。
4. `smt_completeness/threats/baseline.py` 只是可选保留模块；若要复核外部威胁种子，可单独调用，不把 18 条种子的覆盖率当作报告阅读主路径。

## 4.7 典型场景 D：判断一条新需求是否有害

本 CLI 没有单独「审查一条新规则」子命令，但可以：

1. 复制 `ir_openclaw.yaml`，追加候选规则（kind/decision 必须匹配）。
2. 跑 `--no-complete`，比较 `MustAllow` 是否被破坏：看 H1、C3，以及抽检 §5 工作流对应状态的 D 是否从 Allow 变成 Deny。
3. 设计场景四（禁止读取所有 config）会打到 §5「本地读取不含凭据的配置」——表现为 floor 被破坏、冗余/收紧贡献差。可用 JSON 前后对比 `tightening` 与抽检 `decide_py`。

在 Python 里：

```python
from smt_completeness.extractor import load_offline_ir
from smt_completeness.compiler import decide_py, must_allow
from smt_completeness.state_space import State
from smt_completeness.vocab import Operation, ResourceClass, TargetZone, Decision

p = load_offline_ir()
s = State(Operation.READ, ResourceClass.CONFIG, TargetZone.LOCAL, frozenset())
print(decide_py(s, p), must_allow(s, p))  # 预期 Allow / True
```

## 4.8 部署与验证中的预期现象（不是故障）

| 现象 | 原因 | 建议 |
| --- | --- | --- |
| C3 重叠五千余 | Deny 覆盖 Challenge 是 §6.3 | 看示例，不要清零为目标 |
| R4 又冗余又可收紧 | 同一覆盖关系 | 文档仍保留「必须再判断」叙事 |
| 补全后 V_unspecified_challenge 不变 | 未表态默认 Challenge 不会自动升成 Deny | 要补凭据写入需改种子驱动或手写规则 |
| H1 非 tight | 至少 §4 可上调 | 按 A4 汇报 |
| 倒挂计数非 0 | 记忆 vs 上下文 | 对照原文 §2.3 |
| 分析 1–3 分钟 | BDD/Z3 分析耗时 | 正常 |
| PowerShell 打印乱码 | 控制台代码页 | 读文件 |
| `git add .` 想加一堆 `_*.py` | 已 gitignore `/_*.py` | 不要强行加 |

## 4.9 Debug 流程

按层缩小，不要一上来改算法。

### 0）环境

| 症状 | 处理 |
| --- | --- |
| `No module named smt_completeness` | 在仓库根设 `PYTHONPATH`，或 `pip install -e .`（若以后加 pyproject） |
| `No module named z3` | `pip install -r requirements.txt` |
| 根目录 pytest 扫到奇怪文件 | 确认 `pytest.ini` 的 `testpaths = tests` |
| `gh` / 中文路径 | 与本工具无关 |

### 1）CLI 立刻失败

| 异常 | 含义 |
| --- | --- |
| `离线模式仅支持 YAML IR` | 给了 `.md` 却没 `--use-llm` |
| `IR 自检未通过：重复 id=...` | YAML 两条同一 id |
| `恒假规则=...` | 条件在词表下不可能为真（如 flag 既 true 又 false） |
| `kind=... 要求 decision=...` | kind 与 0/1/2 不一致 |
| `未知 flag` | 拼写不在 `ALL_FLAGS` |
| `请设置环境变量 OPENAI_API_KEY` / `DEEPSEEK_API_KEY` | `--use-llm` 缺密钥 |

### 2）报告数字「看起来不对」

1. 确认跑的是**当前代码**（重新 `cli`，不要只看旧 `_demo_out`）。
2. 核对 `coverage.v_explicit + coverage.v_unspecified_allow + coverage.v_unspecified_challenge == 122880`。
3. C3 对账失败会 **assert 崩掉**（BDD 计数与 Z3 witness 不一致）——属于实现级 bug，应带 traceback 报修，而不是调阈值。
4. 威胁基线结果突变：是否改了 `threat_seed.yaml` 或 IR。

### 3）LLM 抽取质量差

- 先离线 fixture 证明分析器健康。
- 检查模型是否遵守 schema（instructor 会重试 3 次）。
- 分段/缩短文档；确认用的是带 §2–§6 的全文。
- DeepSeek 与 OpenAI 结构化能力不同，可换 `--llm-model`。

### 4）补全不收敛或 todos 非空

- 读 stdout「人工复核项」；实现把文案放在 `CompletionResult.manual_review_todos`（CLI 只打长度）。可在 Python 里 `run_completion(load_offline_ir())` 打印 `todos`。
- 不单调：新规则不应让任何状态变得更宽松；若发生则是 cube 与 D 的 bug。
- `V_unspecified_allow` 不降：cube 可能与已有规则重叠或泛化失败。

### 5）性能

单项慢：C4 对每条规则做全空间等价（离线 24 条仍可秒到十几秒）；报告任务会串行跑全部分析。生产路径依赖 BDD/Z3，不应在分析或补全循环里调用 `all_states()`；该接口只用于调试。

### 6）从测试定位模块

```powershell
python -m pytest tests/test_compiler.py tests/test_coverage.py tests/test_baseline.py -v
```

e2e：

```powershell
python -m pytest tests/test_cli_e2e.py -v
```

## 4.10 自己改 IR 时的最小规范

1. 只使用 `vocab.py` 中的枚举与 flag。
2. `kind` 与 `decision` 对齐：deny↔2，challenge↔1，allow↔0。
3. 改完：

```powershell
python -c "from smt_completeness.extractor import load_offline_ir, self_check; p=load_offline_ir('你的.yaml'); print(self_check(p))"
python -m smt_completeness.cli --doc 你的.yaml --out out-try --no-complete
```

4. 不要提交密钥、`out/`、`.smt2` 产物（已 gitignore `*.smt2` 与 `out/`）。

---

# 附录

## A. 判定等级速查

| 值 | 名称 | 文档语言 |
| --- | --- | --- |
| 0 | Allow | 可保留 / 默认本地读列 |
| 1 | Challenge | 必须进一步判断 / LLM 兜底 |
| 2 | Deny | 强制拒绝边界 |

比较：数值更大 = 更严格。单调补全只允许 ≥。

## B. 离线 24 条规则与文档的对应（记忆用）

- §3：R3.1.1–R3.1.7 凭据/敏感/外发污点；R3.2.* 破坏与削弱控制；R3.3.* 持久化与提权；R3.4.1 侦察；R3.5.1 供应链
- §4：R4.1 普通文件外发；R4.2 写 config；R4.3 删源码
- §5：R5.1–R5.8 本地读/列/写/执行与内发普通文件

完整 YAML：`smt_completeness/data/ir_openclaw.yaml`。

## C. 延伸阅读顺序

1. 本文第一、三、四部分（先会用、会读报告）
2. `Abstract_Access_Control_Requirements.md`
3. 设计简化版 MVP spec
4. `docs/research/01-formal-methods-survey.md`（文献与 tightness 教训）
5. `docs/research/03-threat-baseline.md`（120 条种子与结构性缺口）

## D. 版本与范围声明

手册对应仓库实现（含 DeepSeek 提供方、kind↔decision 校验、C3 重叠规则子集、cube 字面打印、离线非 YAML 拒绝）。若代码变更，以 `cli.py` / `report.py` 为准，并重跑第四节清单更新数字。
