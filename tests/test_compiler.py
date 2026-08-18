import z3

from smt_completeness.compiler import (
    decide_py, is_default_allow, must_allow, build_env, find_witness, export_smtlib,
)
from smt_completeness.ir import Condition, Rule, RuleKind, Priority, Policy
from smt_completeness.state_space import State, all_states
from smt_completeness.vocab import Operation, ResourceClass, TargetZone, Decision


def _deny_read_credential():
    return Rule(id="D1", source_anchor="§3.1", kind=RuleKind.MANDATORY_DENY,
                condition=Condition(operation=[Operation.READ, Operation.LIST],
                                    resource_class=[ResourceClass.CREDENTIAL]),
                decision=Decision.DENY, priority=Priority.MANDATORY,
                extraction_confidence="high")


def _allow_read_normal_local():
    return Rule(id="A1", source_anchor="§5", kind=RuleKind.MAY_ALLOW,
                condition=Condition(operation=[Operation.READ],
                                    resource_class=[ResourceClass.NORMAL_FILE],
                                    target_zone=[TargetZone.LOCAL]),
                decision=Decision.ALLOW, priority=Priority.LEARNED,
                extraction_confidence="high")


def test_decide_precedence_and_default():
    p = Policy(rules=[_deny_read_credential(), _allow_read_normal_local()])
    deny_s = State(Operation.READ, ResourceClass.CREDENTIAL, TargetZone.LOCAL, frozenset())
    allow_s = State(Operation.READ, ResourceClass.NORMAL_FILE, TargetZone.LOCAL, frozenset())
    # 无规则命中 + 无风险 + read + local => 默认 Allow
    default_allow_s = State(Operation.READ, ResourceClass.UNKNOWN, TargetZone.LOCAL, frozenset())
    # 无规则命中 + 非 read/list => 默认 Challenge
    default_chal_s = State(Operation.WRITE, ResourceClass.UNKNOWN, TargetZone.LOCAL, frozenset())
    assert decide_py(deny_s, p) == Decision.DENY
    assert decide_py(allow_s, p) == Decision.ALLOW
    assert decide_py(default_allow_s, p) == Decision.ALLOW
    assert decide_py(default_chal_s, p) == Decision.CHALLENGE


def test_default_allow_blocked_by_flag():
    s = State(Operation.READ, ResourceClass.UNKNOWN, TargetZone.LOCAL,
              frozenset({"destructive"}))
    assert is_default_allow(s) is False


def test_must_allow_subtracts_deny():
    p = Policy(rules=[_deny_read_credential(), _allow_read_normal_local()])
    allow_s = State(Operation.READ, ResourceClass.NORMAL_FILE, TargetZone.LOCAL, frozenset())
    assert must_allow(allow_s, p) is True


def test_z3_witness_agrees_with_python():
    p = Policy(rules=[_deny_read_credential()])
    # 找一个 D==Deny 的状态
    w = find_witness(p, lambda z: z.D == int(Decision.DENY))
    assert w is not None
    assert decide_py(w, p) == Decision.DENY


def test_z3_matches_python_on_all_states_sample():
    p = Policy(rules=[_deny_read_credential(), _allow_read_normal_local()])
    env = build_env(p)
    # 抽样 200 个状态，Z3 求值应等于 decide_py
    for i, s in enumerate(all_states()):
        if i % 600 != 0:
            continue
        env.solver.push()
        env.solver.add(env.state_eq(s))
        assert env.solver.check() == z3.sat
        m = env.solver.model()
        d_z3 = m.eval(env.D, model_completion=True).as_long()
        env.solver.pop()
        assert d_z3 == int(decide_py(s, p))


def test_export_smtlib_writes_file(tmp_path):
    p = Policy(rules=[_deny_read_credential()])
    out = tmp_path / "policy.smt2"
    export_smtlib(p, str(out))
    text = out.read_text(encoding="utf-8")
    assert "declare" in text or "assert" in text
