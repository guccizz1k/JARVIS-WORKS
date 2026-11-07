#!/usr/bin/env bash
# V22.3 Codespaces tool-only setup. Never connects to or changes Supabase.
set -euo pipefail
umask 077
if [[ "${CODESPACES:-}" != "true" ]]; then
  printf '%s\n' 'BLOCKED: This bootstrap is only permitted in an approved GitHub Codespace.' >&2
  exit 2
fi
if [[ "${1:---prepare}" != "--prepare" || $# -gt 1 ]]; then
  printf '%s\n' 'Usage: bash scripts/ops/jw_v223_codespace_bootstrap.sh --prepare' >&2
  exit 2
fi
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'BLOCKED: Docker-in-Docker daemon is not ready.' >&2
  exit 2
fi
need_pg17=0
for client in pg_dump pg_restore psql; do
  if ! command -v "$client" >/dev/null 2>&1 ||
     ! "$client" --version | grep -Eq 'PostgreSQL\) (17|1[89]|[2-9][0-9])\.'; then
    need_pg17=1
  fi
done
if [[ "$need_pg17" -eq 1 ]]; then
  # Official signed PostgreSQL APT repository; never curl|bash.
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends postgresql-common ca-certificates
  if [[ ! -x /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh ]]; then
    printf '%s\n' 'BLOCKED: signed PGDG repository helper is unavailable.' >&2
    exit 2
  fi
  sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh -y
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends postgresql-client-17
fi
python3 -m pip install --disable-pip-version-check -r requirements-postgres-check.txt
python3 -m scripts.ops.jw_v223_codespace_check
