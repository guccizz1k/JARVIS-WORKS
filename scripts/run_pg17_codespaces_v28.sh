#!/usr/bin/env bash
# JARVIS WORKS V2.8 — disposable PostgreSQL 17 live RLS verification.
# Requires an existing Codespace with Docker and network access for postgres:17,
# Python 3.12, and psycopg installation. Does not touch customer/production DBs.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CONTAINER=""
WORK=""
EVIDENCE="$ROOT/pg17_rls_gate_result.txt"
CLEANUP_BAD=0
cleanup() {
  local result="$1"
  trap - EXIT
  if [[ -n "$CONTAINER" ]]; then
    if ! docker rm -f "$CONTAINER" >/dev/null 2>&1; then
      echo 'FAIL: disposable PostgreSQL container cleanup failed' >&2
      CLEANUP_BAD=1
    fi
  fi
  if [[ -n "$WORK" ]]; then
    rm -rf -- "$WORK" || CLEANUP_BAD=1
  fi
  if (( CLEANUP_BAD )); then result=1; fi
  case "$result" in
    0) echo 'PASS: PostgreSQL 17 live RLS attacks and ephemeral cleanup completed' | tee -a "$EVIDENCE" ;;
    2) echo 'NOT RUN: prerequisite missing or live gate not executed' | tee -a "$EVIDENCE" ;;
    *) echo 'FAIL: live gate or cleanup failed — do not publish or deploy' | tee -a "$EVIDENCE" ;;
  esac
  exit "$result"
}
trap 'cleanup "$?"' EXIT

notrun() { echo "NOT RUN: $1" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || notrun 'Docker CLI not installed in this environment'
command -v python3 >/dev/null 2>&1 || notrun 'Python 3 missing'
command -v sha256sum >/dev/null 2>&1 || notrun 'sha256sum missing'
docker info >/dev/null 2>&1 || notrun 'Docker daemon not accessible'
# V2.1 historical manifests MUST NOT be rewritten. V2.8 checks only the
# current isolated-live-gate executable surface against a dedicated manifest.
[[ -f V2_8_PG_GATE_SHA256.txt ]] || notrun 'V2.8 gate source manifest missing'
if ! sha256sum --check --status V2_8_PG_GATE_SHA256.txt; then
  echo 'FAIL: V2.8 PostgreSQL gate executable source integrity mismatch' >&2
  exit 1
fi
# Prevent invoking this launcher against unknown / production project layouts.
[[ -f security/pg_rls_test_fixture.sql && -f scripts/run_postgres_isolation_ci.py ]] || notrun 'RLS fixture or runner missing'

WORK="$(mktemp -d "${TMPDIR:-/tmp}/jw-pg17-test.XXXXXXXX")"
chmod 700 "$WORK"
python3 -m venv "$WORK/venv" || notrun 'Cannot create temporary Python environment'
"$WORK/venv/bin/python" -m pip --disable-pip-version-check -q install -r requirements-postgres-check.txt \
  || notrun 'psycopg installation unavailable'

# Use only a fresh, randomly named, disposable postgres:17 container.
# Docker publishes a random localhost-only host port. No production credentials.
PGPASSWORD="$(python3 -c 'import secrets;print(secrets.token_urlsafe(36))')"
NAME="jw-pg17-gate-$(python3 -c 'import secrets;print(secrets.token_hex(6))')"
CONTAINER="$(docker run --rm -d --name "$NAME" \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD="$PGPASSWORD" \
  -e POSTGRES_DB=postgres -p 127.0.0.1::5432 postgres:17)" \
  || notrun 'Unable to start disposable postgres:17 Docker container'

READY=0
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres -d postgres >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
(( READY )) || { echo 'FAIL: isolated PostgreSQL 17 failed readiness check' >&2; exit 1; }
BINDING="$(docker port "$CONTAINER" 5432/tcp | head -n1)"
[[ "$BINDING" =~ ^127\.0\.0\.1:[0-9]+$ ]] || { echo 'FAIL: Docker port not bound exclusively to loopback' >&2; exit 1; }
PORT="${BINDING##*:}"
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo 'FAIL: invalid isolated PostgreSQL port' >&2; exit 1; }

printf 'JARVIS WORKS V2.8 — PostgreSQL 17 live attack gate\n' > "$EVIDENCE"
printf 'Source: %s\n' "$(sha256sum security/postgres_rls_proposal.sql | cut -d' ' -f1)" >> "$EVIDENCE"
printf 'Mode: disposable Docker PostgreSQL; synthetic data only\n' >> "$EVIDENCE"
set +e
JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE \
JW_PG_CI_ROOT_DSN="postgresql://postgres:${PGPASSWORD}@127.0.0.1:${PORT}/postgres" \
"$WORK/venv/bin/python" -m scripts.run_postgres_isolation_ci_v28 2>&1 | tee -a "$EVIDENCE"
RESULT=${PIPESTATUS[0]}
set -e
exit "$RESULT"
