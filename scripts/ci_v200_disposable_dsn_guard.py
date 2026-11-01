"""V20.0 isolated review DSN hardening: 30+ hostile connection alternatives.

Does not connect to any database or mutate shared data.
"""
from __future__ import annotations

import os
from psycopg.conninfo import make_conninfo
from scripts.review import pg_import_preview_v199 as m

ROLE_WRITER = "jw_ci_v199_import_writer"
ROLE_APPROVER = "jw_ci_v194_approver"
ROLE_ROOT = "postgres"


def main() -> None:
    os.environ["JW_ENV"] = "test"
    os.environ["JW_PG_CI_ALLOW"] = "ONLY_EPHEMERAL_LOCAL_DATABASE"
    good = lambda role: make_conninfo(
        "postgresql://postgres:synthetic-not-a-secret@127.0.0.1:5432/postgres",
        user=role)
    for role in (ROLE_ROOT, ROLE_APPROVER, ROLE_WRITER):
        assert m._ci_local_dsn(good(role), role), ("good_local", role)
    # These strings must never authorize local-only synthetic DB credentials.
    bad = [
        ("wrong_host", lambda r: make_conninfo(good(r), host="db.example.net")),
        ("host_alias", lambda r: make_conninfo(good(r), host="localhost")),
        ("wrong_port", lambda r: make_conninfo(good(r), port=5433)),
        ("wrong_database", lambda r: make_conninfo(good(r), dbname="customer")),
        ("wrong_user", lambda r: make_conninfo(good(r), user="postgres" if r!=ROLE_ROOT else ROLE_WRITER)),
        ("hostaddr_override", lambda r: make_conninfo(good(r), hostaddr="198.51.100.3")),
        ("service_override", lambda r: make_conninfo(good(r), service="external")),
        ("socket_override", lambda r: make_conninfo(good(r), host="/var/run/postgresql")),
        ("multiple_hosts", lambda r: make_conninfo(good(r), host="127.0.0.1,remote.example.net")),
        ("multiple_ports", lambda r: make_conninfo(good(r), port="5432,5432")),
        ("options_override", lambda r: make_conninfo(good(r), options="-c search_path=public")),
        ("passfile_override", lambda r: make_conninfo(good(r), passfile="/tmp/elsewhere")),
        ("target_session_attrs", lambda r: make_conninfo(good(r), target_session_attrs="read-write")),
        ("channel_binding", lambda r: make_conninfo(good(r), channel_binding="require")),
        ("uri_host_lookalike", lambda r: "postgresql://"+r+":pw@127.0.0.1.evil.test:5432/postgres"),
        ("uri_db_lookalike", lambda r: "postgresql://"+r+":pw@127.0.0.1:5432/postgres_extra"),
        ("uri_credential_lookalike", lambda r: "postgresql://"+r+":127.0.0.1%3A5432%2Fpostgres@evil.test:5432/postgres"),
        ("uri_user_lookalike", lambda r: "postgresql://"+r+"-suffix:pw@127.0.0.1:5432/postgres"),
        ("uri_extra_query_hostaddr", lambda r: good(r)+" hostaddr=203.0.113.5"),
        ("invalid_scheme", lambda r: "http://"+r+":pw@127.0.0.1:5432/postgres"),
        ("empty_string", lambda r: ""),
        ("none", lambda r: None),
        ("number", lambda r: 33),
        ("list_value", lambda r: ["postgresql://fake"]),
        ("nonsense_options", lambda r: "not a valid postgres conninfo"),
        ("uri_missing_host", lambda r: "postgresql://"+r+":pw@/postgres"),
        ("uri_missing_database", lambda r: "postgresql://"+r+":pw@127.0.0.1:5432/"),
        ("uri_ipv6", lambda r: "postgresql://"+r+":pw@[::1]:5432/postgres"),
        ("url_query_service", lambda r: good(r)+"?service=outside"),
        ("uri_two_hosts", lambda r: "postgresql://"+r+":pw@127.0.0.1,other.example:5432/postgres"),
    ]
    checked=0
    for role in (ROLE_ROOT, ROLE_APPROVER, ROLE_WRITER):
        for label,make in bad:
            candidate=make(role)
            assert not m._ci_local_dsn(candidate, role), ("unexpected_dsn_accept", label,role)
            checked+=1
    m.configure_disposable_writer(good(ROLE_WRITER))
    m.configure_disposable_approver(good(ROLE_APPROVER), b"x"*32)
    for label,make in bad:
        try:
            m.configure_disposable_writer(make(ROLE_WRITER))
        except RuntimeError:
            pass
        else:
            raise AssertionError(("writer_bypass",label))
        try:
            m.configure_disposable_approver(make(ROLE_APPROVER), b"x"*32)
        except RuntimeError:
            pass
        else:
            raise AssertionError(("approver_bypass",label))
        checked+=2
    for bad_key in (b"", b"x"*31, b"x"*33, "x"*32, None):
        try:
            m.configure_disposable_approver(good(ROLE_APPROVER),bad_key)
        except RuntimeError:
            pass
        else:
            raise AssertionError("wrong_approval_key_type_or_size")
        checked+=1
    os.environ["JW_ENV"]="production"
    try:
        m.configure_disposable_writer(good(ROLE_WRITER))
    except RuntimeError:
        pass
    else:
        raise AssertionError("production_guard_bypass")
    checked+=1
    print(f"PASS V200: {checked} adverse DSN/key/env cases + 3 valid loopback cases; no DB access")


if __name__=="__main__":
    main()
