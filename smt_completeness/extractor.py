import os

import yaml
from pydantic import BaseModel

from .ir import Policy
from .state_space import all_states

_DEFAULT_IR = os.path.join(os.path.dirname(__file__), "data", "ir_openclaw.yaml")


class SelfCheckReport(BaseModel):
    total_rules: int
    id_unique: bool
    duplicate_ids: list[str]
    vacuous_rule_ids: list[str]
    ok: bool


def load_offline_ir(path: str | None = None) -> Policy:
    path = path or _DEFAULT_IR
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return Policy(**data)


def _duplicate_ids(policy: Policy) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for rule in policy.rules:
        if rule.id in seen and rule.id not in duplicates:
            duplicates.append(rule.id)
        seen.add(rule.id)
    return duplicates


def _vacuous_ids(policy: Policy) -> list[str]:
    """Return rules that match no state in the finite state space."""
    states = list(all_states())
    vacuous: list[str] = []
    for rule in policy.rules:
        if not any(rule.condition.matches(state) for state in states):
            vacuous.append(rule.id)
    return vacuous


def self_check(policy: Policy) -> SelfCheckReport:
    duplicate_ids = _duplicate_ids(policy)
    vacuous_rule_ids = _vacuous_ids(policy)
    id_unique = not duplicate_ids
    ok = id_unique and not vacuous_rule_ids
    return SelfCheckReport(
        total_rules=len(policy.rules),
        id_unique=id_unique,
        duplicate_ids=duplicate_ids,
        vacuous_rule_ids=vacuous_rule_ids,
        ok=ok,
    )


def extract(
    doc_path: str,
    use_llm: bool = False,
    provider: str = "openai",
    model: str | None = None,
) -> Policy:
    """Load the offline IR by default; optionally extract IR with an LLM."""
    if not use_llm:
        if doc_path.endswith((".yaml", ".yml")):
            return load_offline_ir(doc_path)
        raise ValueError(
            f"离线模式仅支持 YAML IR 文件（.yaml/.yml），收到: {doc_path!r}。"
            "请提供 YAML 路径，或使用 --use-llm 从自然语言文档抽取。"
        )
    return _extract_with_llm(doc_path, provider=provider, model=model)


def _extract_with_llm(
    doc_path: str,
    provider: str = "openai",
    model: str | None = None,
) -> Policy:  # pragma: no cover
    from .llm_client import build_instructor_client, resolve_model

    client = build_instructor_client(provider)
    resolved_model = resolve_model(provider, model)
    with open(doc_path, encoding="utf-8") as f:
        doc = f.read()
    prompt = (
        "你是访问控制需求形式化助手。请把下面的自然语言需求文档抽取为结构化 IR，"
        "只能使用受控词表（Operation/ResourceClass/TargetZone/flag 名单），"
        "每条规则给出 source_anchor 溯源。\n\n" + doc
    )
    policy: Policy = client.chat.completions.create(
        model=resolved_model,
        response_model=Policy,
        messages=[{"role": "user", "content": prompt}],
        max_retries=3,
    )
    return policy
