from enum import Enum, IntEnum


class Operation(str, Enum):
    READ = "read"
    WRITE = "write"
    SEND = "send"
    EXECUTE = "execute"
    DELETE = "delete"
    LIST = "list"


class ResourceClass(str, Enum):
    CREDENTIAL = "credential"
    SYSTEM_SENSITIVE = "system_sensitive"
    AGENT_PRIVATE_CONTEXT = "agent_private_context"
    AGENT_MEMORY = "agent_memory"
    PRIVATE_DATA = "private_data"
    CONFIG = "config"
    SOURCE_CODE = "source_code"
    NORMAL_FILE = "normal_file"
    EXTERNAL_SERVICE = "external_service"
    UNKNOWN = "unknown"


class TargetZone(str, Enum):
    LOCAL = "local"
    INTERNAL = "internal"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class Decision(IntEnum):
    ALLOW = 0
    CHALLENGE = 1
    DENY = 2


RISK_FEATURES = [
    "weakens_control",     # §3.2 关闭 firewall/TLS/audit
    "persistence",         # §3.3 cron/systemd/authorized_keys/hook
    "privilege_esc",       # §3.3 sudo/setuid/LD_PRELOAD
    "supply_chain_exec",   # §3.5 install/build/CI 内隐藏执行
    "destructive",         # §3.2 rm -rf/mkfs/shred/format
    "recon_scan",          # §3.4 nmap/masscan/网段扫描
]

TAINT_FEATURES = [
    "taint_credential",    # 会话已继承凭据内容
    "taint_private_data",  # 会话已继承私人数据
    "taint_session_data",  # 会话已继承 session 数据
]

ALL_FLAGS = RISK_FEATURES + TAINT_FEATURES

# 越大越敏感；external_service / unknown 不参与敏感度偏序（返回 None）
# 注意 agent_private_context 与 agent_memory 同级（spec §5.5）
_SENSITIVITY = {
    ResourceClass.CREDENTIAL: 7,
    ResourceClass.SYSTEM_SENSITIVE: 6,
    ResourceClass.AGENT_PRIVATE_CONTEXT: 5,
    ResourceClass.AGENT_MEMORY: 5,
    ResourceClass.PRIVATE_DATA: 4,
    ResourceClass.CONFIG: 3,
    ResourceClass.SOURCE_CODE: 2,
    ResourceClass.NORMAL_FILE: 1,
}


def sensitivity_rank(rc: ResourceClass) -> int | None:
    return _SENSITIVITY.get(rc)
