from pydantic import BaseModel

from ..compiler import decide_py
from ..ir import Condition, Policy, Provenance, RuleKind
from ..state_space import State
from ..vocab import Decision, Operation, ResourceClass, TargetZone, sensitivity_rank
from .consistency import state_to_dict


class GapCandidate(BaseModel):
    operation: Operation
    resource_class: ResourceClass
    target_zone: list[TargetZone]
    flag_true: list[str]
    flag_false: list[str]
    kind: RuleKind
    evidence_rule_id: str
    witness: dict
    witness_decision_before: int
    witness_decision_after: int

    def to_condition(self) -> Condition:
        return Condition(
            operation=[self.operation],
            resource_class=[self.resource_class],
            target_zone=list(self.target_zone),
            flag_true=list(self.flag_true),
            flag_false=list(self.flag_false),
        )


class EvidenceReport(BaseModel):
    gaps: list[GapCandidate]
    justified_gap_count: int


def _cached_decide(policy: Policy):
    cache: dict[State, Decision] = {}

    def decide(state: State) -> Decision:
        hit = cache.get(state)
        if hit is None:
            hit = decide_py(state, policy)
            cache[state] = hit
        return hit

    return decide


def enumerate_justified_gaps(policy: Policy) -> EvidenceReport:
    decide = _cached_decide(policy)
    grouped: dict[tuple, GapCandidate] = {}
    ranked = [rc for rc in ResourceClass if sensitivity_rank(rc) is not None]

    for rule in policy.rules:
        if rule.provenance is not Provenance.EXTRACTED:
            continue
        if rule.kind not in (RuleKind.MANDATORY_DENY, RuleKind.MUST_CHALLENGE):
            continue
        operations = rule.condition.operation or list(Operation)
        resources = rule.condition.resource_class or ranked
        zone = (
            rule.condition.target_zone[0]
            if rule.condition.target_zone
            else TargetZone.LOCAL
        )
        flags = frozenset(rule.condition.flag_true)
        for operation in operations:
            for rc_low in resources:
                rank_low = sensitivity_rank(rc_low)
                if rank_low is None:
                    continue
                s_low = State(operation, rc_low, zone, flags)
                if not rule.condition.matches(s_low):
                    continue
                if decide(s_low) != rule.decision:
                    continue
                for rc_high in ranked:
                    if rc_high == rc_low:
                        continue
                    rank_high = sensitivity_rank(rc_high)
                    if rank_high is None or rank_high < rank_low:
                        continue
                    s_high = State(operation, rc_high, zone, flags)
                    d_high = decide(s_high)
                    if int(d_high) >= int(rule.decision):
                        continue
                    key = (
                        operation,
                        rc_high,
                        tuple(rule.condition.target_zone),
                        tuple(rule.condition.flag_true),
                        tuple(rule.condition.flag_false),
                    )
                    if key in grouped:
                        continue
                    grouped[key] = GapCandidate(
                        operation=operation,
                        resource_class=rc_high,
                        target_zone=list(rule.condition.target_zone),
                        flag_true=list(rule.condition.flag_true),
                        flag_false=list(rule.condition.flag_false),
                        kind=rule.kind,
                        evidence_rule_id=rule.id,
                        witness=state_to_dict(s_high),
                        witness_decision_before=int(d_high),
                        witness_decision_after=int(rule.decision),
                    )

    gaps = list(grouped.values())
    return EvidenceReport(gaps=gaps, justified_gap_count=len(gaps))
