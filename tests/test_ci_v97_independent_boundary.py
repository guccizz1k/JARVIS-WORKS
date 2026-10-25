"""Independent V9.7 catalog checks use synthetic connections, never a live DB."""
import json

import pytest

from scripts import ci_v97_independent_boundary as gate


ENV = {"JW_ENV": "review", "JW_V97_LIVE_ACK": "READ_ONLY_SUPAVISOR_ACCEPTANCE_V97"}


class Cursor:
    def __init__(self, connection):
        self.db = connection
        self.query = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params=None):
        self.db.queries.append((query, params))
        self.query = query
        if self.db.behavior.get("query_error"):
            raise RuntimeError("secret-password customer@example.invalid")

    def fetchone(self):
        b = self.db.behavior
        kind = self.db.kind
        if self.query == gate.LOGIN_SQL:
            row = ["postgres", gate.LOGINS[kind], gate.LOGINS[kind], True, False,
                   False, False, False, False, False, 17, "on", True,
                   101 if kind == "auth" else 102]
            for index, value in b.get("login", {}).items():
                row[index] = value
            return tuple(row)
        if self.query == gate.LOGIN_MEMBERSHIP_SQL:
            return b.get("login_membership", (True, True, False, False, False, False))
        if self.query == gate.RAW_PRIVILEGES_SQL:
            return (b.get("raw_grants", False),)
        if self.query == gate.STAGE_SQL:
            row = [gate.LOGINS[kind], gate.STAGES[kind], False, False,
                   False, False, False, False, False, "on"]
            for index, value in b.get("stage", {}).items():
                row[index] = value
            return tuple(row)
        if self.query == gate.STAGE_MEMBERSHIP_SQL:
            return b.get("stage_membership", (False, False, False, False))
        raise AssertionError("Unexpected synthetic metadata query")

    def fetchall(self):
        assert self.query == gate.TABLES_SQL
        rows = [(schema, table, True, True, False, False)
                for schema, tables in (("public", gate.EXPECTED_TABLES),
                                       ("jw_dev", gate.STAGE_REQUIRED_TABLES))
                for table in sorted(tables)]
        transform = self.db.behavior.get("tables")
        return transform(rows) if transform else rows


class Connection:
    def __init__(self, kind, **behavior):
        self.kind, self.behavior = kind, behavior
        self.queries = []
        self.rolled_back = self.closed = False

    def cursor(self):
        return Cursor(self)

    def rollback(self):
        self.rolled_back = True
        if self.behavior.get("rollback_error"):
            raise RuntimeError("secret-password")

    def close(self):
        self.closed = True
        if self.behavior.get("close_error"):
            raise RuntimeError("secret-password")


def run(behavior=None, *, env=ENV):
    dbs = []
    opts = []

    def connect(dsn, **kwargs):
        kind = "auth" if dsn == "synthetic-auth" else "trade"
        db = Connection(kind, **((behavior or {}) if kind == "auth" else {}))
        dbs.append(db)
        opts.append(kwargs)
        return db

    result = gate.check_independent_boundaries(
        connector=connect, trade_dsn="synthetic-trade", auth_dsn="synthetic-auth", env=env)
    return result, dbs, opts


def test_catalog_pass_has_precise_scope_and_two_independent_readonly_rollbacks():
    result, dbs, opts = run()
    assert result["decision"] == "PASS"
    assert result["catalog_only"] is True
    assert result["tenant_row_isolation"] == "NOT RUN"
    assert result["production_cutover"] is False
    assert result["public_application_tables"] == 35
    assert result["jw_dev_tables"] == 4
    assert len(dbs) == 2 and dbs[0] is not dbs[1]
    assert all(db.rolled_back and db.closed for db in dbs)
    for db in dbs:
        queries = [q for q, _ in db.queries]
        assert queries[0] == "SET TRANSACTION READ ONLY"
        assert "SET LOCAL ROLE " + gate.STAGES[db.kind] in queries
        assert all(q.startswith(("SELECT", "SET TRANSACTION READ ONLY", "SET LOCAL ROLE"))
                   for q in queries)
    assert opts == [{"sslmode": "verify-full", "connect_timeout": 5}] * 2


@pytest.mark.parametrize("env", [{}, {"JW_ENV": "production"},
                                  {**ENV, "JW_V97_LIVE_ACK": "wrong"}])
def test_opt_in_rejects_before_any_connection(env):
    result, dbs, _ = run(env=env)
    assert result["decision"] == "BLOCKED" and not dbs


@pytest.mark.parametrize("index,value", [
    (0, "other_db"), (1, "postgres"), (2, "jw_app_dev"), (3, False), (4, True),
    (5, True), (6, True), (7, True), (8, True), (9, True), (10, 16), (11, "off"),
    (12, False), (13, None),
])
def test_gateway_identity_noinherit_admin_replication_pg17_tls_and_readonly(index, value):
    result, dbs, _ = run({"login": {index: value}})
    assert result["decision"] == "BLOCKED"
    assert all(db.rolled_back and db.closed for db in dbs)


@pytest.mark.parametrize("membership", [
    (False, True, False, False, False, False),
    (True, False, False, False, False, False),
    (True, True, True, False, False, False),
    (True, True, False, True, False, False),
    (True, True, False, False, True, False),
    (True, True, False, False, False, True),
])
def test_membership_rejects_cross_members_even_when_set_is_false(membership):
    result, _, _ = run({"login_membership": membership})
    assert result["decision"] == "BLOCKED"


def test_raw_gateway_cannot_have_direct_table_grants():
    assert run({"raw_grants": True})[0]["decision"] == "BLOCKED"


@pytest.mark.parametrize("index,value", [
    (0, "postgres"), (1, "jw_app_dev"), (2, True), (3, True),
    (4, True), (5, True), (6, True), (7, True), (8, True), (9, "off"),
])
def test_adopted_stage_is_nonlogin_noinherit_nonprivileged_and_readonly(index, value):
    assert run({"stage": {index: value}})[0]["decision"] == "BLOCKED"


@pytest.mark.parametrize("index", range(4))
def test_adopted_stage_cannot_have_cross_membership_or_set(index):
    membership = [False] * 4
    membership[index] = True
    assert run({"stage_membership": tuple(membership)})[0]["decision"] == "BLOCKED"


def alter_table(schema, table, index, value):
    def change(rows):
        return [tuple(value if i == index else item for i, item in enumerate(row))
                if row[:2] == (schema, table) else row for row in rows]
    return change


@pytest.mark.parametrize("schema", ["public", "jw_dev"])
@pytest.mark.parametrize("index,value", [(2, False), (3, False), (4, True), (5, True)])
def test_force_rls_owner_membership_and_direct_payment_insert_are_required(schema, index, value):
    result, _, _ = run({"tables": alter_table(schema, "payments", index, value)})
    assert result["decision"] == "BLOCKED"


@pytest.mark.parametrize("schema", ["public", "jw_dev"])
def test_required_tables_cannot_be_missing(schema):
    result, _, _ = run({"tables": lambda rows: [r for r in rows
                                               if r[:2] != (schema, "payments")]})
    assert result["decision"] == "BLOCKED"


def test_every_discovered_stage_table_requires_force_rls():
    result, _, _ = run({"tables": lambda rows: rows + [
        ("jw_dev", "extra_stage_table", True, False, False, False)]})
    assert result["decision"] == "BLOCKED"


@pytest.mark.parametrize("failure", ["query_error", "rollback_error", "close_error"])
def test_errors_are_redacted_and_connections_always_close(failure):
    result, dbs, _ = run({failure: True})
    assert result["decision"] == "BLOCKED"
    assert all(db.rolled_back and db.closed for db in dbs)
    assert "secret-password" not in json.dumps(result)
    assert "customer@" not in json.dumps(result)


def test_second_connection_error_rolls_back_and_closes_first_without_leaking():
    first = Connection("auth")
    calls = []

    def connect(dsn, **kwargs):
        calls.append(dsn)
        if len(calls) == 1:
            return first
        raise RuntimeError("secret-password")

    result = gate.check_independent_boundaries(connector=connect, trade_dsn="trade",
                                               auth_dsn="auth", env=ENV)
    assert result["decision"] == "BLOCKED"
    assert first.rolled_back and first.closed
    assert "secret-password" not in json.dumps(result)


def test_one_reused_connection_is_not_independent():
    db = Connection("auth")
    result = gate.check_independent_boundaries(connector=lambda *a, **kw: db,
                                               trade_dsn="trade", auth_dsn="auth", env=ENV)
    assert result["decision"] == "BLOCKED"
    assert db.rolled_back and db.closed


def test_same_backend_pid_is_not_independent():
    assert run({"login": {13: 102}})[0]["decision"] == "BLOCKED"


def test_catalog_drift_between_sessions_is_blocked():
    result, _, _ = run({"tables": lambda rows: rows + [
        ("jw_dev", "new_stage_table", True, True, False, False)]})
    assert result["decision"] == "BLOCKED"
