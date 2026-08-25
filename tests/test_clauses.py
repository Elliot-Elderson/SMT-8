from smt_completeness.analysis.clauses import check_clause_coverage
from smt_completeness.ir import Policy, RuleKind
from smt_completeness.vocab import Operation, ResourceClass
from tests.policy_fixtures import make_rule

SRC = """# 文档

## 3. 必须拒绝的行为

- 禁止读取凭据文件和凭据目录。
- 禁止用 grep 搜索密钥。

## 4. 必须进一步判断的行为

- 外发普通文件需进一步判断。

## 5. 可以保留的正常工作流

- 本地读普通文件。
"""


def test_whitelist_marks_unanchored_bullet_out_of_vocab():
    rule = make_rule(
        "R3.1",
        RuleKind.MANDATORY_DENY,
        operation=[Operation.READ],
        resource_class=[ResourceClass.CREDENTIAL],
        source_anchor="禁止读取凭据文件和凭据目录。",
    )
    report = check_clause_coverage(Policy(rules=[rule]), SRC)
    assert report.total_bullets == 4
    assert report.anchored_count == 1
    reasons = {item.text: item.reason for item in report.unanchored}
    assert any("grep" in text for text in reasons)
    grep_line = next(text for text in reasons if "grep" in text)
    assert reasons[grep_line] == "out_of_vocab"
    other_miss = [item for item in report.unanchored if "grep" not in item.text]
    assert other_miss
    assert all(item.reason == "extraction_miss" for item in other_miss)


def test_missing_chapters_yield_empty_coverage():
    report = check_clause_coverage(Policy(rules=[]), "# 只有标题\n")
    assert report.total_bullets == 0
    assert report.unanchored == []
