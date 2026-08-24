from smt_completeness.ir import Condition, Priority, Provenance, Rule, RuleKind
from smt_completeness.vocab import Decision, Operation, ResourceClass, TargetZone


def make_rule(
    id: str,
    kind: RuleKind,
    *,
    operation: list[Operation] | None = None,
    resource_class: list[ResourceClass] | None = None,
    target_zone: list[TargetZone] | None = None,
    flag_true: list[str] | None = None,
    flag_false: list[str] | None = None,
    source_anchor: str = "s",
    provenance: Provenance = Provenance.EXTRACTED,
) -> Rule:
    decision = {
        RuleKind.MANDATORY_DENY: Decision.DENY,
        RuleKind.MUST_CHALLENGE: Decision.CHALLENGE,
        RuleKind.MAY_ALLOW: Decision.ALLOW,
    }[kind]
    priority = Priority.MANDATORY if kind != RuleKind.MAY_ALLOW else Priority.LEARNED
    return Rule(
        id=id,
        source_anchor=source_anchor,
        kind=kind,
        condition=Condition(
            operation=operation or [],
            resource_class=resource_class or [],
            target_zone=target_zone or [],
            flag_true=flag_true or [],
            flag_false=flag_false or [],
        ),
        decision=decision,
        priority=priority,
        extraction_confidence="high",
        provenance=provenance,
    )


def deny_destructive() -> Rule:
    return make_rule("D-dest", RuleKind.MANDATORY_DENY, flag_true=["destructive"])


def deny_read_private_context() -> Rule:
    return make_rule(
        "D-ctx",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ, Operation.LIST],
        resource_class=[ResourceClass.AGENT_PRIVATE_CONTEXT],
    )


def allow_read_normal_local() -> Rule:
    return make_rule(
        "A-nf",
        RuleKind.MAY_ALLOW,
        operation=[Operation.READ],
        resource_class=[ResourceClass.NORMAL_FILE],
        target_zone=[TargetZone.LOCAL],
    )
