import z3
from pydantic import BaseModel

from .analysis.coverage import check_coverage
from .analysis.monotonicity import check_monotonicity, find_inversion_pair
from .analysis.redundancy import check_redundancy
from .bdd_env import BDDEnv
from .compiler import (
    decide_py,
    find_witness,
    is_monotone,
    is_vacuous,
    preserves_mustallow,
)
from .cubes import Cube, generalize, literal_count
from .ir import Condition, Policy, Priority, Provenance, Rule, RuleKind
from .state_space import State
from .vocab import Decision, Operation, ResourceClass, TargetZone, sensitivity_rank


def verify_monotone(old: Policy, new: Policy) -> bool:
    """∀s. D_new(s) >= D_old(s)：只收紧不放宽（委托 Z3 实现）。"""
    return is_monotone(old, new)


class CompletionRound(BaseModel):
    round_index: int
    v_unspecified_before: int
    v_unspecified_after: int
    inversion_count_before: int
    inversion_count_after: int
    added_rule_ids: list[str]
    removed_rule_ids: list[str]
    narrowed_rule_ids: list[str]
    skipped: list[str]
    monotone_ok: bool


class CompletionResult(BaseModel):
    rounds: list[CompletionRound]
    final_policy: Policy
    converged: bool
    initial_policy: Policy


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _make_syn_rule(
    rule_id: str,
    kind: RuleKind,
    condition: Condition,
    source_anchor: str,
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
    )


def _cube_to_condition(cube: Cube) -> Condition:
    return Condition(
        operation=[Operation(o) for o in cube.operation],
        resource_class=[ResourceClass(r) for r in cube.resource_class],
        target_zone=[TargetZone(t) for t in cube.target_zone],
        flag_true=list(cube.flag_true),
        flag_false=list(cube.flag_false),
    )


def _cond_literal_count(cond: Condition) -> int:
    return (
        bool(cond.operation)
        + bool(cond.resource_class)
        + bool(cond.target_zone)
        + len(cond.flag_true)
        + len(cond.flag_false)
    )


def _passes_gates(base_policy: Policy, candidate_rule: Rule) -> bool:
    if _cond_literal_count(candidate_rule.condition) > 3:
        return False
    candidate = Policy(rules=base_policy.rules + [candidate_rule])
    return (
        is_monotone(base_policy, candidate)
        and preserves_mustallow(base_policy, candidate)
        and not is_vacuous(base_policy, candidate_rule)
    )


# ---------------------------------------------------------------------------
# Phase 1: Hygiene
# ---------------------------------------------------------------------------


def _hygiene_phase(policy: Policy) -> tuple[Policy, list[str], list[str], list[str]]:
    """Remove redundant rules; narrow MUST_CHALLENGE rules covered by Deny."""
    # Redundancy removal via policies_equivalent
    redundancy = check_redundancy(policy)
    redundant_ids = set(redundancy.redundant_rule_ids)
    rules_kept = [r for r in policy.rules if r.id not in redundant_ids]
    removed_ids = list(redundant_ids)

    current = Policy(rules=rules_kept)
    env = BDDEnv(current)
    deny_bdd = env._kind(RuleKind.MANDATORY_DENY)

    narrowed_ids: list[str] = []
    skipped_ids: list[str] = []
    new_rules: list[Rule] = []

    for rule in current.rules:
        if rule.kind != RuleKind.MUST_CHALLENGE:
            new_rules.append(rule)
            continue

        match_bdd = env.match_rule(rule)
        active = match_bdd & env.valid & ~deny_bdd

        if env.count(active) == 0:
            # Completely shadowed by deny rules — drop it
            removed_ids.append(rule.id)
            continue

        # Find a seed in the still-effective region via Z3
        def _make_constraint(r: Rule):
            def _c(z3env):
                return z3.And(
                    z3env.match_expr(r),
                    z3.Not(z3env._kind_or(RuleKind.MANDATORY_DENY)),
                )
            return _c

        seed = find_witness(current, _make_constraint(rule))
        if seed is not None:
            cube = generalize(env, seed, active)
            if cube is not None and literal_count(cube) <= 3:
                new_cond = _cube_to_condition(cube)
                new_rules.append(rule.model_copy(update={"condition": new_cond}))
                narrowed_ids.append(rule.id)
                continue

        skipped_ids.append(rule.id)
        new_rules.append(rule)

    return Policy(rules=new_rules), removed_ids, narrowed_ids, skipped_ids


# ---------------------------------------------------------------------------
# Phase 2: Inversion alignment
# ---------------------------------------------------------------------------


def _inversion_phase(
    policy: Policy,
    round_idx: int,
    seq: list[int],
) -> tuple[Policy, list[str], list[str]]:
    """Fix one strict-rank inversion by synthesizing on the high-rank side."""
    pair = find_inversion_pair(policy)
    if pair is None:
        return policy, [], []

    s_high, s_low = pair
    target = decide_py(s_low, policy)
    added_ids: list[str] = []
    skipped_ids: list[str] = []

    # k=2 cube: (op, rc) of the high-sensitivity side — keeps the fix targeted
    # to the specific operation that caused the inversion so alignment for equal-
    # rank resources (e.g. AGENT_MEMORY) is not perturbed by a wildcard-op Deny.
    cond = Condition(
        operation=[s_high.operation],
        resource_class=[s_high.resource_class],
    )

    kinds = (
        (RuleKind.MANDATORY_DENY, RuleKind.MUST_CHALLENGE)
        if target is Decision.DENY
        else (RuleKind.MUST_CHALLENGE,)
    )

    for kind in kinds:
        seq[0] += 1
        rule_id = f"SYN-{round_idx}-{seq[0]}"
        rule = _make_syn_rule(rule_id, kind, cond, "补全 · 倒挂对齐")

        if _passes_gates(policy, rule):
            added_ids.append(rule_id)
            return Policy(rules=policy.rules + [rule]), added_ids, skipped_ids

        skipped_ids.append(rule_id)

    return policy, added_ids, skipped_ids


# ---------------------------------------------------------------------------
# Phase 3: Unspecified coverage
# ---------------------------------------------------------------------------


def _align_kind_for_cube(cube: Cube, policy: Policy) -> RuleKind:
    """Choose decision strength by comparing same/higher-rank resources."""
    if not cube.operation:
        # Wildcard op: skip align, use Challenge
        return RuleKind.MUST_CHALLENGE

    if not cube.target_zone:
        # Wildcard zone: skip align rather than spreading a local-only Deny.
        return RuleKind.MUST_CHALLENGE

    if not cube.resource_class:
        # Wildcard rc: cannot align; use Challenge (never Deny all-rc)
        return RuleKind.MUST_CHALLENGE

    cube_rc = ResourceClass(cube.resource_class[0])
    cube_rank = sensitivity_rank(cube_rc)
    if cube_rank is None:
        return RuleKind.MUST_CHALLENGE

    flags = frozenset(cube.flag_true)

    def _slice_max_d(op: Operation, tz: TargetZone) -> int:
        max_d: int = int(Decision.ALLOW)
        for rc in ResourceClass:
            rc_rank = sensitivity_rank(rc)
            if rc_rank is not None and rc_rank >= cube_rank:
                seed = State(op, rc, tz, flags)
                d = int(decide_py(seed, policy))
                if d > max_d:
                    max_d = d
        return max_d

    ops = [Operation(value) for value in cube.operation]
    zones = [TargetZone(value) for value in cube.target_zone]

    if len(ops) > 1 or len(zones) > 1:
        if all(
            _slice_max_d(op, tz) == int(Decision.DENY)
            for op in ops
            for tz in zones
        ):
            return RuleKind.MANDATORY_DENY
        return RuleKind.MUST_CHALLENGE

    if _slice_max_d(ops[0], zones[0]) == int(Decision.DENY):
        return RuleKind.MANDATORY_DENY
    return RuleKind.MUST_CHALLENGE


def _covers_default_allow(cube: Cube) -> bool:
    """Return True if the cube potentially covers DefaultAllow states.

    DefaultAllow states: op ∈ {read, list}, tz=local, no flags.
    A cube covers them when no dimension excludes them.
    """
    if cube.flag_true:
        # Requires a flag — DefaultAllow has no flags
        return False
    if cube.operation and not (set(cube.operation) & {"read", "list"}):
        return False
    if cube.target_zone and "local" not in cube.target_zone:
        return False
    return True


def _unspecified_phase(
    policy: Policy,
    round_idx: int,
    seq: list[int],
) -> tuple[Policy, list[str], list[str]]:
    """Synthesize rules for the unspecified region."""
    cov = check_coverage(policy)
    if cov.v_unspecified == 0:
        return policy, [], []

    added_ids: list[str] = []
    skipped_ids: list[str] = []
    current_rules = list(policy.rules)

    for cube in cov.unspecified_cubes:
        kind = _align_kind_for_cube(cube, policy)

        # Forbidden: Deny for DefaultAllow unspecified
        if kind == RuleKind.MANDATORY_DENY and _covers_default_allow(cube):
            kind = RuleKind.MUST_CHALLENGE

        seq[0] += 1
        rule_id = f"SYN-{round_idx}-{seq[0]}"
        cond = _cube_to_condition(cube)
        rule = _make_syn_rule(rule_id, kind, cond, "补全 · 未表态显式化")

        current_base = Policy(rules=current_rules)
        if _passes_gates(current_base, rule):
            current_rules.append(rule)
            added_ids.append(rule_id)
        else:
            skipped_ids.append(rule_id)

    return Policy(rules=current_rules), added_ids, skipped_ids


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run_completion(policy: Policy, max_rounds: int = 5) -> CompletionResult:
    """Three-phase monotonic closed-loop completion: hygiene → inversion → unspecified."""
    initial_policy = policy.model_copy(deep=True)
    current = policy.model_copy(deep=True)
    rounds: list[CompletionRound] = []
    seq: list[int] = [0]
    converged = False

    for i in range(max_rounds):
        cov_before = check_coverage(current)
        mono_before = check_monotonicity(current)
        v_unspec_before = cov_before.v_unspecified
        inv_before = mono_before.inversion_count

        policy_at_start = current

        # Phase 1: Hygiene
        current, removed_ids, narrowed_ids, hygiene_skipped = _hygiene_phase(current)

        # Phase 2: Inversion alignment
        current, inv_added, inv_skipped = _inversion_phase(current, i, seq)

        # Phase 3: Unspecified coverage
        current, unspec_added, unspec_skipped = _unspecified_phase(current, i, seq)

        monotone_ok = is_monotone(policy_at_start, current)
        added_ids = inv_added + unspec_added
        skipped_ids = hygiene_skipped + inv_skipped + unspec_skipped

        if not monotone_ok:
            skipped_ids = skipped_ids + removed_ids + narrowed_ids + added_ids
            current = policy_at_start
            removed_ids = []
            narrowed_ids = []
            added_ids = []

        cov_after = check_coverage(current)
        mono_after = check_monotonicity(current)
        v_unspec_after = cov_after.v_unspecified
        inv_after = mono_after.inversion_count

        rounds.append(
            CompletionRound(
                round_index=i,
                v_unspecified_before=v_unspec_before,
                v_unspecified_after=v_unspec_after,
                inversion_count_before=inv_before,
                inversion_count_after=inv_after,
                added_rule_ids=added_ids,
                removed_rule_ids=removed_ids,
                narrowed_rule_ids=narrowed_ids,
                skipped=skipped_ids,
                monotone_ok=monotone_ok,
            )
        )

        # Stop when neither metric improved (hygiene alone still counts as a round)
        if v_unspec_after >= v_unspec_before and inv_after >= inv_before:
            converged = v_unspec_after == 0 and inv_after == 0
            break

        if v_unspec_after == 0 and inv_after == 0:
            converged = True
            break

    return CompletionResult(
        rounds=rounds,
        final_policy=current,
        converged=converged,
        initial_policy=initial_policy,
    )
