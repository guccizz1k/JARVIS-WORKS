#!/usr/bin/env bash
# V5.8 extends proven V5.7 historical PG17 chain in a disposable container.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v sha256sum >/dev/null || { echo 'NOT RUN: no sha256sum'; exit 2; }
for v in V2_8 V3_5 V3_6 V3_7 V3_8 V3_9 V4_0 V4_1 V4_2 V4_3 V4_4 V4_5 V4_6 V4_7 V4_8 V4_9 V5_0 V5_1 V5_2 V5_3 V5_4 V5_5 V5_6 V5_7 V5_8; do
  f="${v}_PG_GATE_SHA256.txt"
  [[ -f "$f" ]] || { echo "NOT RUN: missing historical manifest $f"; exit 2; }
  sha256sum --check --status "$f" || { echo "FAIL: integrity $f"; exit 1; }
done
jw_env="${JW_ENV:-}"
[[ "${jw_env,,}" != production ]] || { echo 'NOT RUN: production prohibited'; exit 2; }
for v in 35 36 37 38 39 40 41 42 43 44 45 46 47 48 50 52 53 54 55 56 57 58; do
  export "JW_PG_LAB_V${v}=ONLY_DISPOSABLE_LAB"
done
export JW_PG_OUTBOX_V51=ONLY_DISPOSABLE_LAB JW_PG_RELAY_V52=ONLY_DISPOSABLE_LAB
JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE python3 -m scripts.test_mutation_snapshot_v54 || { echo 'FAIL: old V5.4 fixture'; exit 1; }
CONTAINER=""; WORK=""; BAD_CLEANUP=0
EVIDENCE="$ROOT/pg17_v58_gate_result.txt"
cleanup() {
  local ret="$1"
  trap - EXIT
  if [[ -n "$CONTAINER" ]]; then docker rm -f "$CONTAINER" >/dev/null 2>&1 || BAD_CLEANUP=1; fi
  if [[ -n "$WORK" ]]; then rm -rf -- "$WORK" || BAD_CLEANUP=1; fi
  if (( BAD_CLEANUP )); then ret=1; fi
  case "$ret" in
    0) echo 'PASS: V5.8 isolated PG17 recipient identity, receipt SHA256, exact replay, RLS and Docker cleanup (cutover DENIED)' | tee -a "$EVIDENCE" ;;
    2) echo 'NOT RUN: V5.8 prerequisites missing' | tee -a "$EVIDENCE" ;;
    *) echo 'FAIL: V5.8 PG17 integration or cleanup' | tee -a "$EVIDENCE" ;;
  esac
  exit "$ret"
}
trap 'cleanup "$?"' EXIT
notrun(){ echo "NOT RUN: $1" >&2; exit 2; }
command -v docker >/dev/null || notrun 'Docker missing'
command -v python3 >/dev/null || notrun 'Python missing'
docker info >/dev/null 2>&1 || notrun 'Docker daemon missing'
[[ -f security/pg_rls_test_fixture.sql && -f scripts/run_postgres_isolation_ci_v28.py ]] || notrun 'supervisor missing'
WORK="$(mktemp -d "${TMPDIR:-/tmp}/jw-pg17-v58.XXXXXXXX")"
chmod 700 "$WORK"
python3 -m venv "$WORK/venv" || notrun 'venv missing'
"$WORK/venv/bin/python" -m pip --disable-pip-version-check -q install -r requirements-postgres-check.txt -r requirements-postgres-lab-v35.txt -r requirements.txt || notrun 'pip dependencies missing'
PGPASSWORD="$(python3 -c 'import secrets;print(secrets.token_urlsafe(36))')"
NAME="jw-pg17-v58-$(python3 -c 'import secrets;print(secrets.token_hex(6))')"
CONTAINER="$(docker run --rm -d --name "$NAME" -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD="$PGPASSWORD" -e POSTGRES_DB=postgres -p 127.0.0.1::5432 postgres:17)" || notrun 'temporary PG17 container refused'
READY=0
for _ in $(seq 1 60); do
  if docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U postgres -d postgres >/dev/null 2>&1; then READY=1; break; fi
  sleep 1
done
(( READY )) || { echo 'FAIL: temporary PostgreSQL17 readiness timeout'; exit 1; }
BINDING="$(docker port "$CONTAINER" 5432/tcp | head -n1)"
[[ "$BINDING" =~ ^127\.0\.0\.1:[0-9]+$ ]] || { echo 'FAIL: loopback-only PG17 port required'; exit 1; }
PORT="${BINDING##*:}"
printf 'JARVIS-WORKS V5.8 | isolated receiving employee receipt proof\nNo customer data or production cutover\n' > "$EVIDENCE"
set +e
JW_PG_CI_ALLOW=ONLY_EPHEMERAL_LOCAL_DATABASE JW_PG_CI_ROOT_DSN="postgresql://postgres:${PGPASSWORD}@127.0.0.1:${PORT}/postgres" "$WORK/venv/bin/python" -m scripts.run_postgres_isolation_ci_v58 2>&1 | tee -a "$EVIDENCE"
code=${PIPESTATUS[0]}
set -e
exit "$code"
