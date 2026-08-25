from collections import defaultdict

import z3
from pydantic import BaseModel

from .analysis.consistency import state_to_dict
from .analysis.coverage import check_coverage
from .analysis.defects import silent_permission_states
from .analysis.evidence import enumerate_justified_gaps
from .analysis.monotonicity import check_monotonicity
from .compiler import (
    find_witness,
    is_monotone,
    is_vacuous,
    preserves_mustallow,
)
from .ir import Condition, Justification, Policy, Priority, Provenance, Rule, RuleKind
from .state_space import State
from .vocab import Decision


MAX_SYN_LITERALS = 4
MAX_GAP_FIXES = 12


def verify_monotone(old: Policy, new: Policy) -> bool:
    """∀s. D_new(s) >= D_old(s)：只收紧不放宽（委托 Z3 实现）。"""
    return is_monotone(old, new)


class CompletionRound(BaseModel):
    round_index: int
    justified_gap_count_before: int
    justified_gap_count_after: int
    silent_permission_volume_before: int
    silent_permission_volume_after: int
    v_unspecified_before: int
    v_unspecified_after: int
    inversion_count_before: int
    inversion_count_after: int
    added_rule_ids: list[str]
    skipped: list[str]
    monotone_ok: bool


class CompletionResult(BaseModel):
    rounds: list[CompletionRound]
    final_policy: Policy
    converged: bool
    initial_policy: Policy
    remaining_reasons: list[str] = []


def _cond_literal_count(cond: Condition) -> int:
    return (
        bool(cond.operation)
        + bool(cond.resource_class)
        + bool(cond.target_zone)
        + len(cond.flag_true)
        + len(cond.flag_false)
    )


def _make_justified_rule(
    rule_id: str,
    kind: RuleKind,
    condition: Condition,
    source_anchor: str,
    justification: Justification,
) -> Rule:
    decision = Decision.DENY if kind == RuleKind.MANDATORY_DENY else Decision.CHALLENGE
    return Rule(
        id=rule_id,
        source_anchor=source_anchor,
        kind=kind,
        condition=condition,
        decision=decision,
        priority=Priority.MANDATORY,
        extraction_confidence="medium",
        reviewer_status="auto_approved",
        provenance=Provenance.SYNTHESIZED,
        justification=justification,
    )


def _passes_gates(base_policy: Policy, candidate_rule: Rule) -> bool:
    if _cond_literal_count(candidate_rule.condition) > MAX_SYN_LITERALS:
        return False
    candidate = Policy(rules=base_policy.rules + [candidate_rule])
    return (
        is_monotone(base_policy, candidate)
        and preserves_mustallow(base_policy, candidate)
        and not is_vacuous(base_policy, candidate_rule)
    )


def _mustallow_conflict_witness(base: Policy, rule: Rule) -> State | None:
    def constraint(env):
        must = z3.And(
            env._kind_or(RuleKind.MAY_ALLOW),
            z3.Not(env._kind_or(RuleKind.MANDATORY_DENY)),
            z3.Not(env._kind_or(RuleKind.MUST_CHALLENGE)),
        )
        return z3.And(must, env.match_expr(rule))

    return find_witness(base, constraint)


def fix_sensitivity_gaps(
    policy: Policy, round_idx: int, seq: list[int]
) -> tuple[Policy, list[str], list[str]]:
    report = enumerate_justified_gaps(policy)
    added: list[str] = []
    skipped: list[str] = []
    current = policy
    for gap in report.gaps[:MAX_GAP_FIXES]:
        evidence = next(rule for rule in policy.rules if rule.id == gap.evidence_rule_id)
        rule_id = f"SYN-{round_idx}-{seq[0] + 1}"
        seq[0] += 1
        rule = _make_justified_rule(
            rule_id,
            gap.kind,
            gap.to_condition(),
            evidence.source_anchor,
            Justification(
                defect="sensitivity_gap",
                evidence_rule_ids=[gap.evidence_rule_id],
                witness=gap.witness,
                witness_decision_before=gap.witness_decision_before,
                witness_decision_after=gap.witness_decision_after,
            ),
        )
        if _passes_gates(current, rule):
            current = Policy(rules=current.rules + [rule])
            added.append(rule_id)
        else:
            skipped.append(rule_id)
    return current, added, skipped


def fix_silent_permissions(
    policy: Policy, round_idx: int, seq: list[int]
) -> tuple[Policy, list[str], list[str]]:
    grouped: dict[tuple, list] = defaultdict(list)
    for state in silent_permission_states(policy):
        grouped[(state.operation, state.target_zone)].append(state)
    added: list[str] = []
    skipped: list[str] = []
    current = policy
    for (operation, zone), states in grouped.items():
        resources = sorted({state.resource_class for state in states}, key=lambda item: item.value)
        condition = Condition(
            operation=[operation],
            resource_class=resources,
            target_zone=[zone],
        )
        witness = states[0]
        seq[0] += 1
        rule_id = f"SYN-{round_idx}-{seq[0]}"
        rule = _make_justified_rule(
            rule_id,
            RuleKind.MUST_CHALLENGE,
            condition,
            "",
            Justification(
                defect="silent_permission",
                evidence_rule_ids=[],
                witness=state_to_dict(witness),
                witness_decision_before=int(Decision.ALLOW),
                witness_decision_after=int(Decision.CHALLENGE),
            ),
        )
        if _passes_gates(current, rule):
            current = Policy(rules=current.rules + [rule])
            added.append(rule_id)
            continue
        conflict = _mustallow_conflict_witness(current, rule)
        if conflict is not None and conflict.flags:
            lowered = condition.model_copy(
                update={"flag_false": sorted(conflict.flags)}
            )
            if _cond_literal_count(lowered) <= MAX_SYN_LITERALS:
                seq[0] += 1
                retry_id = f"SYN-{round_idx}-{seq[0]}"
                retry = rule.model_copy(
                    update={"id": retry_id, "condition": lowered}
                )
                if _passes_gates(current, retry):
                    current = Policy(rules=current.rules + [retry])
                    added.append(retry_id)
                    skipped.append(rule_id)
                    continue
        skipped.append(rule_id)
    return current, added, skipped


def run_completion(policy: Policy, max_rounds: int = 8) -> CompletionResult:
    initial_policy = policy.model_copy(deep=True)
    current = policy.model_copy(deep=True)
    rounds: list[CompletionRound] = []
    seq = [0]
    converged = False
    remaining_reasons: list[str] = []

    for i in range(max_rounds):
        start = current
        cov_before = check_coverage(current)
        mono_before = check_monotonicity(current)
        gap_before = enumerate_justified_gaps(current).justified_gap_count
        silent_before = len(silent_permission_states(current))

        current, gap_added, gap_skipped = fix_sensitivity_gaps(current, i, seq)
        current, silent_added, silent_skipped = fix_silent_permissions(current, i, seq)
        added = gap_added + silent_added
        skipped = gap_skipped + silent_skipped

        monotone_ok = is_monotone(start, current)
        if not monotone_ok:
            skipped = skipped + added
            current = start
            added = []

        cov_after = check_coverage(current)
        mono_after = check_monotonicity(current)
        gap_after = enumerate_justified_gaps(current).justified_gap_count
        silent_after = len(silent_permission_states(current))

        rounds.append(
            CompletionRound(
                round_index=i,
                justified_gap_count_before=gap_before,
                justified_gap_count_after=gap_after,
                silent_permission_volume_before=silent_before,
                silent_permission_volume_after=silent_after,
                v_unspecified_before=cov_before.v_unspecified,
                v_unspecified_after=cov_after.v_unspecified,
                inversion_count_before=mono_before.inversion_count,
                inversion_count_after=mono_after.inversion_count,
                added_rule_ids=added,
                skipped=skipped,
                monotone_ok=monotone_ok,
            )
        )

        if gap_after == 0 and silent_after == 0:
            converged = True
            break
        if gap_after >= gap_before and silent_after >= silent_before:
            break

    if not converged:
        if enumerate_justified_gaps(current).justified_gap_count:
            remaining_reasons.append("有依据缺口未清零：门禁拒绝或文字数超限")
        if silent_permission_states(current):
            remaining_reasons.append("静默允许未清零：门禁拒绝或文字数超限")

    return CompletionResult(
        rounds=rounds,
        final_policy=current,
        converged=converged,
        initial_policy=initial_policy,
        remaining_reasons=remaining_reasons,
    )
