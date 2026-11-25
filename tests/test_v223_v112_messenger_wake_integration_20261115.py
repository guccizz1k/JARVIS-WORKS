"""Synthetic integration of main V11.2 wake notifications with V22.3's isolated V9 messenger."""
import pytest
from app import pg_v90_integrated_entry as entry
from app.pg_v112_wakeup import WakeHub

class IsolatedApp:
    def __init__(self):
        self.routes=[]
        self.events={}
    def add_api_route(self,path,handler,**kwargs):
        self.routes.append(("api",path))
    def include_router(self,router):
        self.routes.append(("router",router))
    def add_event_handler(self,name,handler):
        self.events[name]=handler

def setup_isolated_routes(monkeypatch):
    app=IsolatedApp()
    capture=[]
    monkeypatch.setattr(entry,"v90_enabled",lambda:True)
    monkeypatch.setattr(entry,"_origins",lambda:frozenset({"https://qa.invalid"}))
    monkeypatch.setattr(entry,"ScopedMessengerGateway",lambda:object())
    monkeypatch.setattr(entry,"create_router",lambda *a,**kw:"synthetic-http-router")
    def realtime(*a,**kw):
        capture.append(kw)
        return "synthetic-ws-router"
    monkeypatch.setattr(entry,"create_realtime_router",realtime)
    return app,capture

def test_default_opt_out_has_no_listener_or_network(monkeypatch):
    monkeypatch.delenv("JW_V112_PG_NOTIFY_ACK",raising=False)
    app,cap=setup_isolated_routes(monkeypatch)
    assert entry.register_v90_messenger(app) is True
    assert len(app.routes)==3 and app.events=={}
    assert cap==[{"allowed_origins":frozenset({"https://qa.invalid"}),"wake_hub":None}]

def test_notify_ack_flag_fails_closed_in_production(monkeypatch):
    monkeypatch.setenv("JW_V112_PG_NOTIFY_ACK","ISOLATED_PG17_REVIEW_ONLY")
    monkeypatch.setenv("JW_ENV","production")
    app,cap=setup_isolated_routes(monkeypatch)
    with pytest.raises(RuntimeError,match="prohibited outside review"):
        entry.register_v90_messenger(app)
    assert app.routes==[] and app.events=={} and cap==[]

def test_notify_ack_review_only_wires_bounded_hub(monkeypatch):
    monkeypatch.setenv("JW_V112_PG_NOTIFY_ACK","ISOLATED_PG17_REVIEW_ONLY")
    monkeypatch.setenv("JW_ENV","test")
    app,cap=setup_isolated_routes(monkeypatch)
    assert entry.register_v90_messenger(app) is True
    assert len(app.routes)==3 and set(app.events)=={"startup","shutdown"}
    hub=cap[0]["wake_hub"]
    assert isinstance(hub,WakeHub) and hub.subscriptions==0 and hub.connected is False

def test_listener_startup_blocks_missing_review_triggers(monkeypatch):
    monkeypatch.setenv("JW_V112_PG_NOTIFY_ACK","ISOLATED_PG17_REVIEW_ONLY")
    monkeypatch.setenv("JW_ENV","test")
    app,_=setup_isolated_routes(monkeypatch)
    class Cursor:
        def __enter__(self):return self
        def __exit__(self,*a):return False
        def execute(self,sql):assert "v112_messenger_wakeup" in sql
        def fetchone(self):return (1,)
    class Connection:
        def __enter__(self):return self
        def __exit__(self,*a):return False
        def transaction(self):return self
        def cursor(self):return Cursor()
    monkeypatch.setattr(entry.stage,"_connect",lambda:Connection())
    assert entry.register_v90_messenger(app) is True
    with pytest.raises(RuntimeError,match="verified message triggers missing"):
        app.events["startup"]()
