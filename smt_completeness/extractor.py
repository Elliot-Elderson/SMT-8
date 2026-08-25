import os

import yaml
import z3
from pydantic import BaseModel

from .compiler import Z3Env, is_vacuous
from .ir import Policy, RuleKind

_DEFAULT_IR = os.path.join(os.path.dirname(__file__), "data", "ir_openclaw.yaml")


class SelfCheckReport(BaseModel):
    total_rules: int
    id_unique: bool
    duplicate_ids: list[str]
    vacuous_rule_ids: list[str]
    tautology_rule_ids: list[str] = []
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
    return [rule.id for rule in policy.rules if is_vacuous(policy, rule)]


def _tautology_ids(policy: Policy) -> list[str]:
    env = Z3Env(policy)
    decision_kinds = (
        RuleKind.MANDATORY_DENY,
        RuleKind.MUST_CHALLENGE,
        RuleKind.MAY_ALLOW,
    )
    tautology_ids: list[str] = []
    seen: set[str] = set()

    def add_rule_id(rule_id: str) -> None:
        if rule_id not in seen:
            tautology_ids.append(rule_id)
            seen.add(rule_id)

    def covers_valid(match: z3.BoolRef) -> bool:
        env.solver.push()
        env.solver.add(z3.Not(match))
        result = env.solver.check()
        env.solver.pop()
        return result == z3.unsat

    for kind in decision_kinds:
        for rule in policy.rules_of_kind(kind):
            if covers_valid(env.match_expr(rule)):
                add_rule_id(rule.id)

        rules = policy.rules_of_kind(kind)
        if rules and covers_valid(env._kind_or(kind)):
            for rule in rules:
                add_rule_id(rule.id)

    return tautology_ids


def self_check(policy: Policy) -> SelfCheckReport:
    duplicate_ids = _duplicate_ids(policy)
    vacuous_rule_ids = _vacuous_ids(policy)
    tautology_rule_ids = _tautology_ids(policy)
    id_unique = not duplicate_ids
    ok = (
        id_unique
        and not vacuous_rule_ids
        and not tautology_rule_ids
        and len(policy.rules) >= 1
    )
    return SelfCheckReport(
        total_rules=len(policy.rules),
        id_unique=id_unique,
        duplicate_ids=duplicate_ids,
        vacuous_rule_ids=vacuous_rule_ids,
        tautology_rule_ids=tautology_rule_ids,
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
    from .llm_client import EXTRACT_TEMPERATURE, build_instructor_client, resolve_model

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
        temperature=EXTRACT_TEMPERATURE,
        max_retries=3,
    )
    return policy
