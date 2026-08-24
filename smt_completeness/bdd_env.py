from dd.autoref import BDD

from .ir import Policy, Rule, RuleKind
from .state_space import EXPECTED_STATE_COUNT, State
from .vocab import ALL_FLAGS, Decision, Operation, ResourceClass, TargetZone


def _exactly_one_expr(names: list[str]) -> str:
    parts = []
    for i, name in enumerate(names):
        bits = [name] + [f"~{other}" for j, other in enumerate(names) if j != i]
        parts.append("(" + " /\\ ".join(bits) + ")")
    return "(" + " \\/ ".join(parts) + ")"


class BDDEnv:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.bdd = BDD()
        self.op_names = [f"op_{item.value}" for item in Operation]
        self.rc_names = [f"rc_{item.value}" for item in ResourceClass]
        self.tz_names = [f"tz_{item.value}" for item in TargetZone]
        self.flag_names = [f"flag_{name}" for name in ALL_FLAGS]
        self.var_names = self.op_names + self.rc_names + self.tz_names + self.flag_names
        self.bdd.declare(*self.var_names)
        valid_expr = " /\\ ".join(
            [
                _exactly_one_expr(self.op_names),
                _exactly_one_expr(self.rc_names),
                _exactly_one_expr(self.tz_names),
            ]
        )
        self.valid = self.bdd.add_expr(valid_expr)
        counted = self.count(self.valid)
        if counted != EXPECTED_STATE_COUNT:
            raise RuntimeError(f"BDD Valid count={counted}, expected {EXPECTED_STATE_COUNT}")

    def count(self, node) -> int:
        return int(self.bdd.count(node, nvars=len(self.var_names)))

    def _and(self, nodes: list):
        acc = self.bdd.true
        for node in nodes:
            acc = acc & node
        return acc

    def _or(self, nodes: list):
        acc = self.bdd.false
        for node in nodes:
            acc = acc | node
        return acc

    def match_rule(self, rule: Rule):
        condition = rule.condition
        parts = []
        if condition.operation:
            parts.append(
                self._or([self.bdd.var(f"op_{item.value}") for item in condition.operation])
            )
        if condition.resource_class:
            parts.append(
                self._or(
                    [self.bdd.var(f"rc_{item.value}") for item in condition.resource_class]
                )
            )
        if condition.target_zone:
            parts.append(
                self._or([self.bdd.var(f"tz_{item.value}") for item in condition.target_zone])
            )
        for flag in condition.flag_true:
            parts.append(self.bdd.var(f"flag_{flag}"))
        for flag in condition.flag_false:
            parts.append(~self.bdd.var(f"flag_{flag}"))
        return self._and(parts) if parts else self.bdd.true

    def any_match(self):
        return self._or(
            [
                self._kind(RuleKind.MANDATORY_DENY),
                self._kind(RuleKind.MUST_CHALLENGE),
                self._kind(RuleKind.MAY_ALLOW),
            ]
        )

    def default_allow(self):
        no_flags = self._and([~self.bdd.var(f"flag_{name}") for name in ALL_FLAGS])
        read_or_list = self.bdd.var("op_read") | self.bdd.var("op_list")
        local = self.bdd.var("tz_local")
        return no_flags & read_or_list & local

    def d_is(self, level: int):
        deny = self._kind(RuleKind.MANDATORY_DENY)
        challenge = self._kind(RuleKind.MUST_CHALLENGE)
        allow = self._kind(RuleKind.MAY_ALLOW)
        default_allow = self.default_allow()
        if level == int(Decision.DENY):
            return deny
        if level == int(Decision.CHALLENGE):
            return ~deny & (challenge | (~allow & ~default_allow))
        if level == int(Decision.ALLOW):
            return ~deny & ~challenge & (allow | default_allow)
        raise ValueError(level)

    def assignment_to_state(self, assignment: dict[str, bool]) -> State:
        operation = self._single_true_enum(assignment, self.op_names, Operation, "op")
        resource_class = self._single_true_enum(
            assignment, self.rc_names, ResourceClass, "resource_class"
        )
        target_zone = self._single_true_enum(assignment, self.tz_names, TargetZone, "target_zone")
        flags = frozenset(
            name.removeprefix("flag_")
            for name in self.flag_names
            if assignment.get(name, False)
        )
        return State(operation, resource_class, target_zone, flags)

    def _kind(self, kind: RuleKind):
        rules = self.policy.rules_of_kind(kind)
        if not rules:
            return self.bdd.false
        return self._or([self.match_rule(rule) for rule in rules])

    def _single_true_enum(self, assignment, names, enum_type, label):
        true_names = [name for name in names if assignment.get(name, False)]
        if len(true_names) != 1:
            raise ValueError(f"assignment must set exactly one {label}: {true_names}")
        return enum_type(true_names[0].split("_", 1)[1])
