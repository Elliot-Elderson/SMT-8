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


def extract(doc_path: str, use_llm: bool = False, model: str = "gpt-4o") -> Policy:
    """Load the offline IR by default; optionally extract IR with an LLM."""
    if not use_llm:
        if doc_path.endswith((".yaml", ".yml")):
            return load_offline_ir(doc_path)
        return load_offline_ir()
    return _extract_with_llm(doc_path, model=model)


def _extract_with_llm(doc_path: str, model: str) -> Policy:  # pragma: no cover
    import instructor
    from openai import OpenAI

    client = instructor.from_openai(OpenAI())
    with open(doc_path, encoding="utf-8") as f:
        doc = f.read()
    prompt = (
        "你是访问控制需求形式化助手。请把下面的自然语言需求文档抽取为结构化 IR，"
        "只能使用受控词表（Operation/ResourceClass/TargetZone/flag 名单），"
        "每条规则给出 source_anchor 溯源。\n\n" + doc
    )
    policy: Policy = client.chat.completions.create(
        model=model,
        response_model=Policy,
        messages=[{"role": "user", "content": prompt}],
        max_retries=3,
    )
    return policy
