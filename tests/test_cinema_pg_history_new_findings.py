"""Exact detector correction contracts for the seven newly reviewed matches."""
import json

import pytest

from scripts import ci_cinema_pg_history_classifier as classifier


COMMIT = "cd081b8d199ba5a70bd79106a7d2eb5569c07bc1"
RULE = "generic-api-key"
FIXTURES = (
    ("008177551274a292b0273fdd45c6afdf0adcea86", ".github/workflows/jw-v223-pg17-s4-real-qa-20261114.yml", 79, 23, 85, "workflow_git_blob_sha_constant"),
    ("e14166f3fd09795092e803f70bba4ef19ed46d4c", ".github/workflows/jw-v223-tls-74-20261114.yml", 65, 23, 85, "workflow_git_blob_sha_constant"),
    ("cdd9b2e6b9335576ab996cee30ee8cbeec7fd6f7", ".github/workflows/jw-v223-exact-sha-274-20261114.yml", 80, 23, 85, "workflow_git_blob_sha_constant"),
    (COMMIT, "tests/test_cinema_pg_y_synthetic_restore.py", 110, 10, 43, "postgres_constraint_identifier"),
    (COMMIT, "tests/test_cinema_pg_m.py", 29, 26, 88, "synthetic_parser_fixture"),
    (COMMIT, "tests/test_cinema_pg_w.py", 170, 10, 34, "postgres_constraint_identifier"),
    (COMMIT, "tests/test_cinema_pg_w_synthetic_restore.py", 89, 10, 43, "postgres_constraint_identifier"),
)


def row_for(fixture):
    commit, path, line, start, end, _ = fixture
    return {
        "RuleID": RULE,
        "Commit": commit,
        "File": path,
        "StartLine": line,
        "EndLine": line,
        "StartColumn": start,
        "EndColumn": end,
    }


@pytest.mark.parametrize("fixture", FIXTURES)
def test_only_exact_historical_match_is_accepted(fixture):
    row = row_for(fixture)
    assert classifier.exact_classification(row) == fixture[-1]
    for field, replacement in {
        "Commit": "0" * 40,
        "File": "app/unrelated.py",
        "RuleID": "unrelated",
        "StartLine": row["StartLine"] + 1,
        "EndLine": row["EndLine"] + 1,
        "StartColumn": row["StartColumn"] + 1,
        "EndColumn": row["EndColumn"] - 1,
        "StartColumn-as-string": str(row["StartColumn"]),
    }.items():
        assert classifier.exact_classification({**row, field.removesuffix("-as-string"): replacement}) is None


def test_extra_match_in_same_line_blocks_full_report(tmp_path):
    report = tmp_path / "scan.json"
    rows = [row_for(fixture) for fixture in FIXTURES]
    report.write_text(json.dumps(rows + [{**rows[0], "StartColumn": 1}]))
    accepted, result = classifier.classify_report(report, 1)
    assert not accepted
    assert result["unreviewed_findings"] == 1
    assert result["reviewed_exact_historical_false_positives"] == len(FIXTURES)


@pytest.mark.parametrize("kind", ["postgres_constraint_identifier", "synthetic_parser_fixture"])
def test_semantics_reject_unrelated_source(kind):
    assert not classifier.semantic_fixture_guard(kind, "target = 'unrelated'")
