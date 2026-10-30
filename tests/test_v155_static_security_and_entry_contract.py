"""Dependency-free V15.5 fail-closed source and API composition checks."""
import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app/pg_delivery_review_api_v154.py"
UI = ROOT / "app/pg_delivery_review_console_v155.py"
LIMIT = ROOT / "app/pg_delivery_request_limit_v155.py"
RESERVE = ROOT / "app/pg_delivery_review_reservation_v151.py"
STAGE = ROOT / "scripts/jw_v104_standalone.py"
PG_POLICIES = ROOT / "scripts/review/v153_restricted_review_writer_candidate.sql"


def test_new_modules_parse_and_do_not_execute_dynamic_python():
    for source in (API, UI, LIMIT, RESERVE):
        tree = ast.parse(source.read_text(), filename=source.name)
        assert isinstance(tree, ast.Module)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in ("eval", "exec", "compile", "__import__")


def test_only_isolated_pg_entrypoint_wires_review_feature():
    source = STAGE.read_text()
    assert source.count("pg_delivery_review_api_v154.register_v154_delivery_review(app)") == 1
    assert "from app import pg_api_v84" in source
    assert "from app import pg_quote_api_v92" in source
    assert "from app.main import" not in source


def test_new_private_http_paths_fail_closed_and_preserve_finance():
    source = API.read_text()
    assert "JW_PG_DELIVERY_REVIEW_V154" in source
    assert "JW_V154_ISSUER_INDEPENDENCE_ACK" in source
    assert "JW_V154_DISPATCH_VERIFY_KEY_HEX" in source
    assert "JW_V154_RECEIPT_VERIFY_KEY_HEX" in source
    for term in ("_origin_checked(request)", "_session_hash(request)",
                 "X-CSRF-Token", 'identity[3] != "admin"',
                 'status": "PENDING_HUMAN_REVIEW"',
                 "register_v155_review_console(app, enabled)"):
        assert term in source
    for prohibited in ("INSERT INTO jw_dev.invoices",
                       "INSERT INTO jw_dev.payments",
                       "UPDATE jw_dev.orders", "service_role"):
        assert prohibited not in source


def test_full_request_body_preparse_cap_and_private_console():
    source = LIMIT.read_text()
    assert "async def limited_receive" in source
    assert "total += len(event.get" in source
    assert "total > _MAX_RAW_BYTES" in source
    assert "content-length" in source
    assert "http.response.start" in source
    ui = UI.read_text()
    for term in ("frame-ancestors 'none'", "default-src 'none'",
                 "aria-live", "lang=", "textContent",
                 "get_delivery_review_status"):
        if term == "get_delivery_review_status":
            continue
        assert term in ui
    assert "innerHTML" not in ui and "eval(" not in ui


def test_restricted_pg_review_role_does_not_grant_signup_or_mutation():
    sql = re.sub(r"--[^\n]*", "", PG_POLICIES.read_text())
    assert sql.count("CREATE POLICY v153_") == 6
    assert sql.count("FOR INSERT TO jw_app_dev") == 3
    assert sql.count("FOR SELECT TO jw_app_dev") == 3
    assert "GRANT SELECT, INSERT ON TABLE" in sql
    assert "review_signup_requests_v151" not in sql
    assert "review_signup_nonces_v151" not in sql
    assert "GRANT ALL" not in sql
    assert "TO PUBLIC" not in sql
