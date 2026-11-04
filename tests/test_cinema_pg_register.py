"""Opt-in registration of the CINEMA trade router (S5). Runs WITHOUT fastapi/psycopg/PostgreSQL by loading
app/pg_cinema_register_v1.py against minimal fakes of its three imports. It proves the gating and the
per-request statement order of the gateway, not real HTTP or a real database."""
from __future__ import annotations

import ast
import importlib.util
import sys
import types
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "app" / "pg_cinema_register_v1.py"
V202 = ROOT / "app" / "pg_review_integrated_v202.py"
GATE = "JW_PG_CINEMA_TRADE_V1"


class _HTTPException(Exception):
    def __init__(self, status_code, detail=None):
        super().__init__(status_code, detail)
        self.status_code, self.detail = status_code, detail


class _Cursor:
    def __init__(self, owner_member):
        self.log, self.owner_member, self.description, self._rows = [], owner_member, None, []

    def execute(self, sql, params=()):
        self.log.append((" ".join(str(sql).split()), tuple(params)))
        if "pg_has_role" in sql:
            self.description, self._rows = None, [(self.owner_member,)]
        elif sql.startswith("SELECT 1"):
            col = types.SimpleNamespace(name="result")
            self.description, self._rows = [col], [(7,)]
        else:
            self.description, self._rows = None, []

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


@pytest.fixture
def reg(monkeypatch):
    state = types.SimpleNamespace(v90_enabled=False, owner_member=False, cursors=[], routers=[], authorize_calls=0)

    fast = types.ModuleType("fastapi")
    fast.HTTPException, fast.Request = _HTTPException, object
    pkg = types.ModuleType("fakepkg")
    pkg.__path__ = []

    v90 = types.ModuleType("fakepkg.pg_v90_integrated_entry")
    v90.v90_enabled = lambda: state.v90_enabled

    @contextmanager
    def validated(session_hash):
        cur = _Cursor(state.owner_member)
        state.cursors.append((session_hash, cur))
        yield cur, ("jw_app_dev", "actor", "org", "admin", "csrf", "Org")

    v90._pg_validated_cursor = validated

    def v90_authorize(request):
        state.authorize_calls += 1
        return types.SimpleNamespace(session_hash="h" * 64, csrf_verified=True)

    v90._authorize = v90_authorize

    trade = types.ModuleType("fakepkg.pg_cinema_trade_v1")
    trade.WRITER_ROLE = "jw_cinema_writer"

    class VerifiedSession:
        def __init__(self, session_hash, csrf_verified):
            self.session_hash, self.csrf_verified = session_hash, csrf_verified

    trade.VerifiedSession = VerifiedSession
    trade.create_router = lambda gateway, authorize: ("router", gateway, authorize)

    for name, mod in (("fastapi", fast), ("fakepkg", pkg), ("fakepkg.pg_v90_integrated_entry", v90),
                      ("fakepkg.pg_cinema_trade_v1", trade)):
        monkeypatch.setitem(sys.modules, name, mod)
    pkg.pg_v90_integrated_entry, pkg.pg_cinema_trade_v1 = v90, trade

    spec = importlib.util.spec_from_file_location("fakepkg.pg_cinema_register_v1", MODULE)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "fakepkg.pg_cinema_register_v1", module)
    spec.loader.exec_module(module)
    monkeypatch.delenv(GATE, raising=False)

    app = types.SimpleNamespace(include_router=lambda r: state.routers.append(r))
    return types.SimpleNamespace(module=module, state=state, app=app, monkeypatch=monkeypatch)


def test_off_by_default_even_when_messenger_stage_is_enabled(reg):
    reg.state.v90_enabled = True
    assert reg.module.register_cinema_trade_v1(reg.app) is False
    assert reg.state.routers == []


@pytest.mark.parametrize("value", ["", "1", "true", "ISOLATED_DEV_MESSENGER_ONLY", "isolated_dev_cinema_trade_only"])
def test_only_the_exact_gate_value_enables_it(reg, value):
    reg.state.v90_enabled = True
    reg.monkeypatch.setenv(GATE, value)
    assert reg.module.register_cinema_trade_v1(reg.app) is False and reg.state.routers == []


def test_gate_without_the_v90_prerequisites_does_not_mount(reg):
    reg.monkeypatch.setenv(GATE, "ISOLATED_DEV_CINEMA_TRADE_ONLY")
    reg.state.v90_enabled = False
    assert reg.module.register_cinema_trade_v1(reg.app) is False and reg.state.routers == []


def test_gate_with_prerequisites_mounts_exactly_one_router_with_converted_authorizer(reg):
    reg.monkeypatch.setenv(GATE, "ISOLATED_DEV_CINEMA_TRADE_ONLY")
    reg.state.v90_enabled = True
    assert reg.module.register_cinema_trade_v1(reg.app) is True
    assert len(reg.state.routers) == 1
    _, gateway, authorize = reg.state.routers[0]
    assert isinstance(gateway, reg.module.ValidatedWriterGateway)
    session = authorize(object())
    assert reg.state.authorize_calls == 1                       # delegated to the reviewed V9.0 check
    assert session.session_hash == "h" * 64 and session.csrf_verified is True


def test_gateway_checks_owner_separation_before_dropping_to_writer_then_runs_sql(reg):
    rows = reg.module.ValidatedWriterGateway().query("s" * 64, "SELECT 1 AS result", ("p",))
    assert rows == [{"result": 7}]
    session_hash, cur = reg.state.cursors[0]
    assert session_hash == "s" * 64
    statements = [s for s, _ in cur.log]
    assert "pg_has_role" in statements[0] and cur.log[0][1] == ("jw_cinema_owner",)
    assert statements[1] == "SET LOCAL ROLE jw_cinema_writer"
    assert statements[2] == "SELECT 1 AS result" and cur.log[2][1] == ("p",)


def test_login_role_that_can_become_the_owner_is_refused_before_any_role_switch_or_sql(reg):
    reg.state.owner_member = True
    with pytest.raises(_HTTPException) as err:
        reg.module.ValidatedWriterGateway().query("s" * 64, "SELECT 1 AS result", ())
    assert err.value.status_code == 503
    statements = [s for s, _ in reg.state.cursors[0][1].log]
    assert len(statements) == 1 and "SET LOCAL ROLE" not in " ".join(statements) and "SELECT 1 AS result" not in statements


def test_module_creates_no_roles_grants_or_ddl():
    text = MODULE.read_text(encoding="utf-8").upper()
    for word in ("CREATE ROLE", "GRANT ", "ALTER ROLE", "CREATE TABLE", "DROP ", "INSERT ", "PASSWORD", "BYPASSRLS", "SECURITY DEFINER"):
        assert word not in text.split('"""', 2)[2], word


def test_v202_registers_it_only_as_optional_after_all_required_and_preflights_the_flag():
    source = V202.read_text(encoding="utf-8")
    tree = ast.parse(source)
    assert "from . import pg_cinema_register_v1 as cinema_trade" in source
    required_block = source.split("required = (", 1)[1].split(")\n    for register, name in required:", 1)[0]
    assert "cinema_trade" not in required_block
    optional_block = source.split("for register in (", 1)[1].split("    ):", 1)[0]
    assert optional_block.strip().splitlines()[-1].strip() == "cinema_trade.register_cinema_trade_v1,"
    assert 'os.environ.get("JW_PG_CINEMA_TRADE_V1") and not cinema_trade.cinema_trade_enabled()' in source
    assert "BLOCKED: CINEMA trade writer prerequisite gate denied" in source
    # the new flag must NOT be part of the set of REQUIRED capabilities (default stays off)
    required_dict = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "_REQUIRED")
    assert "JW_PG_CINEMA_TRADE_V1" not in ast.dump(required_dict)
