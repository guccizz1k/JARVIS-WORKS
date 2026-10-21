#!/usr/bin/env bash
# Review-only V5.5: historical PG17 gates plus signed disposable text-message payload replication.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null 2>&1 || { echo 'NOT RUN: sha256sum unavailable' >&2; exit 2; }
for version in V2_8 V3_5 V3_6 V3_7 V3_8 V3_9 V4_0 V4_1 V4_2 V4_3 V4_4 V4_5 V4_6 V4_7 V4_8 V4_9 V5_0 V5_1 V5_2 V5_3 V5_4 V5_5; do
  manifest="${version}_PG_GATE_SHA256.txt"
  [[ -f "$manifest" ]] || { echo 'NOT RUN: historical manifest absent' >&2; exit 2; }
  sha256sum --check --status "$manifest" || { echo 'FAIL: source integrity altered' >&2; exit 1; }
done
JW_ENV_SAFE="${JW_ENV:-}"
[[ "${JW_ENV_SAFE,,}" != 'production' ]] || { echo 'NOT RUN: production environment refused' >&2; exit 2; }
for version in 35 36 37 38 39 40 41 42 43 44 45 46 47 48 50 52 53 54 55; do
  export "JW_PG_LAB_V${version}=ONLY_DISPOSABLE_LAB"
done
[[ "${JW_PG_LAB_V55:-}" == 'ONLY_DISPOSABLE_LAB' ]] || { echo 'NOT RUN: V5.5 signed relay lab flag missing' >&2; exit 2; }
export JW_PG_OUTBOX_V51=ONLY_DISPOSABLE_LAB
export JW_PG_RELAY_V52=ONLY_DISPOSABLE_LAB
JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE \
python3 -m scripts.test_mutation_snapshot_v54 || { echo 'FAIL: V5.4 source snapshot prerequisite'; exit 1; }
CONTAINER=""
WORK=""
BAD_CLEANUP=0
EVIDENCE="$ROOT/pg17_v55_gate_result.txt"
cleanup() {
  local result="$1"
  trap - EXIT
  if [[ -n "$CONTAINER" ]]; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || BAD_CLEANUP=1
  fi
  if [[ -n "$WORK" ]]; then
    rm -rf -- "$WORK" || BAD_CLEANUP=1
  fi
  if (( BAD_CLEANUP )); then result=1; fi
  case "$result" in
    0) echo 'PASS: V5.5 isolated PG17 full text payload equality, exact replay, signed RLS, checkpoint and Docker cleanup (cutover DENIED)' | tee -a "$EVIDENCE" ;;
    2) echo 'NOT RUN: V5.5 prerequisite missing' | tee -a "$EVIDENCE" ;;
    *) echo 'FAIL: V5.5 integration or cleanup failed' | tee -a "$EVIDENCE" ;;
  esac
  exit "$result"
}
trap 'cleanup "$?"' EXIT
notrun() { echo "NOT RUN: $1" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || notrun 'Docker CLI unavailable'
command -v python3 >/dev/null 2>&1 || notrun 'Python 3 unavailable'
docker info >/dev/null 2>&1 || notrun 'Docker daemon unavailable'
[[ -f security/pg_rls_test_fixture.sql && -f scripts/run_postgres_isolation_ci_v28.py ]] || notrun 'Historical supervisor absent'
WORK="$(mktemp -d "${TMPDIR:-/tmp}/jw-pg17-v55.XXXXXXXX")"
chmod 700 "$WORK"
python3 -m venv "$WORK/venv" || notrun 'Temporary Python environment unavailable'
"$WORK/venv/bin/python" -m pip --disable-pip-version-check -q install \
  -r requirements-postgres-check.txt -r requirements-postgres-lab-v35.txt -r requirements.txt \
  || notrun 'Temporary PostgreSQL Python dependencies unavailable'
PGPASSWORD="$(python3 -c 'import secrets;print(secrets.token_urlsafe(36))')"
NAME="jw-pg17-v55-$(python3 -c 'import secrets;print(secrets.token_hex(6))')"
CONTAINER="$(docker run --rm -d --name "$NAME" \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD="$PGPASSWORD" \
  -e POSTGRES_DB=postgres -p 127.0.0.1::5432 postgres:17)" \
  || notrun 'Disposable postgres:17 container could not start'
READY=0
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres -d postgres >/dev/null 2>&1; then
    READY=1; break
  fi
  sleep 1
done
(( READY )) || { echo 'FAIL: PostgreSQL 17 readiness timeout' >&2; exit 1; }
BINDING="$(docker port "$CONTAINER" 5432/tcp | head -n1)"
[[ "$BINDING" =~ ^127\.0\.0\.1:[0-9]+$ ]] || { echo 'FAIL: loopback-only Docker port required' >&2; exit 1; }
PORT="${BINDING##*:}"
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo 'FAIL: invalid local Docker port' >&2; exit 1; }
printf 'JARVIS-WORKS V5.5 | disposable PG17 synthetic UTF-8 text payload replication rehearsal\n' > "$EVIDENCE"
printf 'No customer data or production changes\n' >> "$EVIDENCE"
set +e
JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE \
JW_PG_CI_ROOT_DSN="postgresql://postgres:${PGPASSWORD}@127.0.0.1:${PORT}/postgres" \
"$WORK/venv/bin/python" -m scripts.run_postgres_isolation_ci_v55 2>&1 | tee -a "$EVIDENCE"
RESULT=${PIPESTATUS[0]}
set -e
exit "$RESULT"
