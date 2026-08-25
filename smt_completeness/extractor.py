import json
import os
from datetime import datetime, timezone

import yaml
import z3
from pydantic import BaseModel, Field

from .compiler import Z3Env, is_vacuous
from .extract_validate import (
    renumber_rules,
    split_decision_chapters,
    validate_extracted_policy,
)
from .ir import Policy, RuleKind

_DEFAULT_IR = os.path.join(os.path.dirname(__file__), "data", "ir_openclaw.yaml")

_EXTRACT_PROMPT = """你是访问控制需求形式化助手。只从「必须拒绝 / 必须进一步判断 / 可以允许」抽判定规则。
禁止把「没有已有策略完整匹配时的默认允许 / LLM 兜底」写成规则。
缺省维度=通配，但禁止五维全空；单维（如只 destructive）允许。
只能使用受控词表，每条给出 source_anchor（必须是原文列表句中的连续片段）。
正例：禁止读取凭据 → mandatory_deny，condition.resource_class=[credential]，operation=[read,list]。
反例：不要把「无策略匹配则 LLM 兜底」写成一条无条件 must_challenge。"""

_CHAPTER_DEFAULTS = {
    "3": RuleKind.MANDATORY_DENY,
    "4": RuleKind.MUST_CHALLENGE,
    "5": RuleKind.MAY_ALLOW,
}


class SelfCheckReport(BaseModel):
    total_rules: int
    id_unique: bool
    duplicate_ids: list[str]
    vacuous_rule_ids: list[str]
    tautology_rule_ids: list[str] = []
    ok: bool


class ExtractQa(BaseModel):
    source_doc: str
    source_sha256: str
    provider: str | None = None
    model: str | None = None
    extraction_mode: str
    temperature: int = 0
    extracted_at: str
    self_check: SelfCheckReport
    kind_counts: dict[str, int]
    warnings: list[str] = Field(default_factory=list)
    skipped_completion: bool = False


def kind_counts(policy: Policy) -> dict[str, int]:
    counts = {kind.value: 0 for kind in RuleKind}
    for rule in policy.rules:
        counts[rule.kind.value] = counts.get(rule.kind.value, 0) + 1
    return counts


def build_extract_qa(
    policy: Policy,
    source_doc: str,
    source_sha256: str,
    self_check: SelfCheckReport,
    provider: str | None = None,
    model: str | None = None,
    extraction_mode: str = "offline",
    warnings: list[str] | None = None,
    skipped_completion: bool = False,
) -> ExtractQa:
    return ExtractQa(
        source_doc=source_doc,
        source_sha256=source_sha256,
        provider=provider,
        model=model,
        extraction_mode=extraction_mode,
        extracted_at=datetime.now(timezone.utc).isoformat(),
        self_check=self_check,
        kind_counts=kind_counts(policy),
        warnings=warnings or [],
        skipped_completion=skipped_completion,
    )


def write_extracted_ir(policy: Policy, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(policy.model_dump(mode="json"), f, allow_unicode=True)


def write_extract_qa(qa: ExtractQa, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(qa.model_dump(mode="json"), f, ensure_ascii=False, indent=2)
        f.write("\n")


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
    return_mode: bool = False,
) -> Policy | tuple[Policy, str]:
    """Load the offline IR by default; optionally extract IR with an LLM."""
    if not use_llm:
        if doc_path.endswith((".yaml", ".yml")):
            policy = load_offline_ir(doc_path)
            return (policy, "offline") if return_mode else policy
        raise ValueError(
            f"离线模式仅支持 YAML IR 文件（.yaml/.yml），收到: {doc_path!r}。"
            "请提供 YAML 路径，或使用 --use-llm 从自然语言文档抽取。"
        )
    policy, mode = _extract_with_llm(doc_path, provider=provider, model=model)
    return (policy, mode) if return_mode else policy


def _extract_with_llm(
    doc_path: str,
    provider: str = "openai",
    model: str | None = None,
) -> tuple[Policy, str]:  # pragma: no cover
    from .llm_client import EXTRACT_TEMPERATURE, build_instructor_client, resolve_model

    client = build_instructor_client(provider)
    resolved_model = resolve_model(provider, model)
    with open(doc_path, encoding="utf-8") as f:
        doc = f.read()
    chapters = split_decision_chapters(doc)

    def create_policy(source_md: str, chapter_default: RuleKind | None) -> Policy:
        prompt = _EXTRACT_PROMPT
        if chapter_default is not None:
            prompt += (
                f"\n本段默认 kind 为 {chapter_default.value}；"
                "若子弹线索与默认冲突，以线索为准。"
            )
        prompt += "\n\n" + source_md
        policy: Policy = client.chat.completions.create(
            model=resolved_model,
            response_model=Policy,
            messages=[{"role": "user", "content": prompt}],
            temperature=EXTRACT_TEMPERATURE,
            max_retries=3,
        )
        validate_extracted_policy(policy, source_md, chapter_default)
        return policy

    if chapters is None:
        policy = create_policy(doc, chapter_default=None)
        merged_rules = renumber_rules(policy.rules, "R")
        mode = "flat"
    else:
        merged_rules = []
        for chapter in ("3", "4", "5"):
            default = _CHAPTER_DEFAULTS[chapter]
            policy = create_policy(chapters[chapter], chapter_default=default)
            merged_rules.extend(renumber_rules(policy.rules, f"R{chapter}"))
        mode = "chapter"

    if not merged_rules:
        raise ValueError("抽取结果为空规则表")
    return Policy(rules=merged_rules), mode
