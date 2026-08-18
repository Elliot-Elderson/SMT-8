from itertools import count
from pathlib import Path
from typing import Callable

import z3

from .ir import Policy, Rule, RuleKind
from .state_space import State
from .vocab import ALL_FLAGS, Decision, Operation, ResourceClass, TargetZone

_READ_LIST = {Operation.READ, Operation.LIST}
_ENV_IDS = count()


def is_default_allow(state: State) -> bool:
    return (
        not state.flags
        and state.operation in _READ_LIST
        and state.target_zone == TargetZone.LOCAL
    )


def decide_py(state: State, policy: Policy) -> Decision:
    if any(
        rule.condition.matches(state)
        for rule in policy.rules_of_kind(RuleKind.MANDATORY_DENY)
    ):
        return Decision.DENY
    if any(
        rule.condition.matches(state)
        for rule in policy.rules_of_kind(RuleKind.MUST_CHALLENGE)
    ):
        return Decision.CHALLENGE
    if any(rule.condition.matches(state) for rule in policy.rules_of_kind(RuleKind.MAY_ALLOW)):
        return Decision.ALLOW
    return Decision.ALLOW if is_default_allow(state) else Decision.CHALLENGE


def must_allow(state: State, policy: Policy) -> bool:
    hits_floor = any(
        rule.condition.matches(state)
        for rule in policy.rules_of_kind(RuleKind.MAY_ALLOW)
    )
    hits_ceiling = any(
        rule.condition.matches(state)
        for rule in policy.rules_of_kind(RuleKind.MANDATORY_DENY)
    )
    hits_challenge = any(
        rule.condition.matches(state)
        for rule in policy.rules_of_kind(RuleKind.MUST_CHALLENGE)
    )
    return hits_floor and not hits_ceiling and not hits_challenge


class Z3Env:
    def __init__(self, policy: Policy):
        self.policy = policy
        prefix = f"smtc_{next(_ENV_IDS)}"

        self.op_sort, op_consts = z3.EnumSort(
            f"{prefix}_Operation", [operation.value for operation in Operation]
        )
        self.rc_sort, rc_consts = z3.EnumSort(
            f"{prefix}_ResourceClass",
            [resource_class.value for resource_class in ResourceClass],
        )
        self.tz_sort, tz_consts = z3.EnumSort(
            f"{prefix}_TargetZone", [target_zone.value for target_zone in TargetZone]
        )
        self._op_map = {
            operation.value: const for operation, const in zip(Operation, op_consts)
        }
        self._rc_map = {
            resource_class.value: const
            for resource_class, const in zip(ResourceClass, rc_consts)
        }
        self._tz_map = {
            target_zone.value: const for target_zone, const in zip(TargetZone, tz_consts)
        }

        self.op = z3.Const(f"{prefix}_op", self.op_sort)
        self.rc = z3.Const(f"{prefix}_rc", self.rc_sort)
        self.tz = z3.Const(f"{prefix}_tz", self.tz_sort)
        self.flag = {name: z3.Bool(f"{prefix}_flag_{name}") for name in ALL_FLAGS}
        self.D = self._build_decision_expr()
        self.solver = z3.Solver()

    def _match_expr(self, rule: Rule) -> z3.BoolRef:
        conds: list[z3.BoolRef] = []
        condition = rule.condition
        if condition.operation:
            conds.append(
                z3.Or(
                    [self.op == self._op_map[operation.value] for operation in condition.operation]
                )
            )
        if condition.resource_class:
            conds.append(
                z3.Or(
                    [
                        self.rc == self._rc_map[resource_class.value]
                        for resource_class in condition.resource_class
                    ]
                )
            )
        if condition.target_zone:
            conds.append(
                z3.Or(
                    [
                        self.tz == self._tz_map[target_zone.value]
                        for target_zone in condition.target_zone
                    ]
                )
            )
        for flag in condition.flag_true:
            conds.append(self.flag[flag])
        for flag in condition.flag_false:
            conds.append(z3.Not(self.flag[flag]))
        return z3.And(conds) if conds else z3.BoolVal(True)

    def match_expr(self, rule: Rule) -> z3.BoolRef:
        return self._match_expr(rule)

    def default_allow_expr(self) -> z3.BoolRef:
        no_flags = z3.And([z3.Not(flag) for flag in self.flag.values()])
        read_or_list = z3.Or(
            self.op == self._op_map[Operation.READ.value],
            self.op == self._op_map[Operation.LIST.value],
        )
        local = self.tz == self._tz_map[TargetZone.LOCAL.value]
        return z3.And(no_flags, read_or_list, local)

    def _kind_or(self, kind: RuleKind) -> z3.BoolRef:
        rules = self.policy.rules_of_kind(kind)
        if not rules:
            return z3.BoolVal(False)
        return z3.Or([self._match_expr(rule) for rule in rules])

    def _build_decision_expr(self) -> z3.ArithRef:
        deny = self._kind_or(RuleKind.MANDATORY_DENY)
        challenge = self._kind_or(RuleKind.MUST_CHALLENGE)
        allow = self._kind_or(RuleKind.MAY_ALLOW)
        return z3.If(
            deny,
            int(Decision.DENY),
            z3.If(
                challenge,
                int(Decision.CHALLENGE),
                z3.If(
                    allow,
                    int(Decision.ALLOW),
                    z3.If(
                        self.default_allow_expr(),
                        int(Decision.ALLOW),
                        int(Decision.CHALLENGE),
                    ),
                ),
            ),
        )

    def state_eq(self, state: State) -> z3.BoolRef:
        conds = [
            self.op == self._op_map[state.operation.value],
            self.rc == self._rc_map[state.resource_class.value],
            self.tz == self._tz_map[state.target_zone.value],
        ]
        for name, flag in self.flag.items():
            conds.append(flag if name in state.flags else z3.Not(flag))
        return z3.And(conds)

    def model_to_state(self, model: z3.ModelRef) -> State:
        op_value = str(model.eval(self.op, model_completion=True))
        rc_value = str(model.eval(self.rc, model_completion=True))
        tz_value = str(model.eval(self.tz, model_completion=True))
        flags = frozenset(
            name
            for name, flag in self.flag.items()
            if z3.is_true(model.eval(flag, model_completion=True))
        )
        return State(Operation(op_value), ResourceClass(rc_value), TargetZone(tz_value), flags)


def build_env(policy: Policy) -> Z3Env:
    return Z3Env(policy)


def find_witness(policy: Policy, constraint: Callable[[Z3Env], z3.BoolRef]) -> State | None:
    env = build_env(policy)
    env.solver.push()
    env.solver.add(constraint(env))
    result = env.solver.check()
    witness = None
    if result == z3.sat:
        candidate = env.model_to_state(env.solver.model())
        env.solver.push()
        env.solver.add(env.state_eq(candidate), constraint(env))
        if env.solver.check() == z3.sat:
            witness = candidate
        env.solver.pop()
    env.solver.pop()
    return witness


def export_smtlib(policy: Policy, path: str) -> None:
    env = build_env(policy)
    decision = z3.Int("decision")
    solver = z3.Solver()
    solver.add(decision == env.D)

    output_path = Path(path)
    output_path.write_text(
        "; SMT-LIB export of the access-control decision function D(state)\n"
        "; Decision encoding: Allow=0, Challenge=1, Deny=2\n"
        f"{solver.to_smt2()}",
        encoding="utf-8",
    )
