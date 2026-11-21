#!/usr/bin/env bash
# Run the same exact-source acceptance steps locally and on a GitHub runner.
set -euo pipefail

candidate_sha=16b06a8da738de1129382cafc10e2b4b5004c424
candidate_tree=799088018c637501c89fa5082b63ec7eec254388
control_sha=e22f66dde4ed552a75ce504147875733d4671ab2
fixture_sha=0446138c10e52d81d99a7592da06e45af269aa77
initial_workflow_sha=05ba6c8c0c0ee77d6c9536df009c332ff2839083
remote_base=b8ee382e6c0fd856c1537d3997c07deef21b69e5
installer_sha=a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338
wrapper="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
: "${JW_CI_ROOT:?Set JW_CI_ROOT to a fresh private output directory}"
test "${JW_CI_ROOT:0:1}" = /
export GIT_NO_REPLACE_OBJECTS=1
source_dir="$JW_CI_ROOT/candidate"
evidence="$JW_CI_ROOT/evidence"
if [[ -n "${DATABASE_URL:-}${JW_PG_ADMIN_DSN:-}${PGHOST:-}${PGHOSTADDR:-}${PGSERVICE:-}${PGPASSWORD:-}${PGPASSFILE:-}${POSTGRES_URL:-}${SUPABASE_DB_URL:-}" ]]; then
    printf '%s\n' 'BLOCKED: inherited database configuration' >&2
    exit 1
fi

if [[ "${1:-}" == source ]]; then
    umask 077
    mkdir "$JW_CI_ROOT"
    mkdir "$evidence"
    exec > >(tee "$evidence/source.log") 2>&1
    cd "$wrapper"
    wrapper_sha="$(git rev-parse HEAD)"
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        test "$GITHUB_REF" = refs/heads/review/jw-v223-strict-history
        test "$GITHUB_SHA" = "$wrapper_sha"
    fi
    test "$(git show -s --format=%P "$initial_workflow_sha")" = "$candidate_sha $fixture_sha"
    git merge-base --is-ancestor "$initial_workflow_sha" HEAD
    test "$(git diff --name-only --no-renames "$candidate_sha" HEAD)" = $'.github/workflows/jw-v223-independent-ci.yml\nscripts/ci_cinema_pg_history_classifier.py\nscripts/ci_v223_independent.sh\ntests/test_cinema_pg_history_new_findings.py'
    test -z "$(git status --porcelain)"
    git worktree add --detach "$source_dir" "$candidate_sha"
    git worktree add -b jw-ci-v222-control "$JW_CI_ROOT/legacy" "$control_sha"
    git worktree add --detach "$JW_CI_ROOT/installer-fixture" "$installer_sha"
    test "$(git -C "$source_dir" rev-parse HEAD^{tree})" = "$candidate_tree"
    test "$(git rev-parse "$fixture_sha:tests/test_messenger_v22.py")" = 2817b8d2c69224dde4ac518118f4d61913285bd2
    printf 'workflow_sha=%s\ncandidate_sha=%s\ncandidate_tree=%s\ncontrol_sha=%s\n' \
        "$wrapper_sha" "$candidate_sha" "$candidate_tree" "$control_sha" > "$evidence/source-ids.txt"
    python -I "$source_dir/scripts/jw_v223_composite_containment.py" \
        --root "$source_dir" --policy-commit "$candidate_sha" | tee "$evidence/composite.json"
    python -I "$JW_CI_ROOT/legacy/scripts/ci_cinema_pg_guard.py" "$JW_CI_ROOT/legacy" | tee "$evidence/legacy.json"
    python - "$evidence/legacy.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as stream:
    result = json.load(stream)
assert result["overall"] == "PASS" and len(result["checks"]) == 12
assert all(check["result"] == "PASS" for check in result["checks"])
PY
    (cd "$JW_CI_ROOT/installer-fixture"; python -I "$source_dir/scripts/ci_rebuild_v79_overlay.py")
    exit
fi

cd "$source_dir"
test "$(git rev-parse HEAD)" = "$candidate_sha"
test "$(git rev-parse HEAD^{tree})" = "$candidate_tree"
git diff --exit-code HEAD --
case "${1:-}" in
    history)
        : "${JW_GITLEAKS:?Provide the repository-pinned Gitleaks executable}"
        scan_dir="$(mktemp -d "$JW_CI_ROOT/history.XXXXXX")"
        wrapper_sha="$(git -C "$wrapper" rev-parse HEAD)"
        git merge-base --is-ancestor "$remote_base" "$wrapper_sha"
        test "$(git rev-parse --is-shallow-repository)" = false
        # Scan the complete publication ancestry without importing unrelated refs.
        git init -q "$scan_dir/repository"
        git -C "$scan_dir/repository" fetch --no-tags "$wrapper" "$wrapper_sha:refs/heads/reviewed"
        test "$(git -C "$scan_dir/repository" rev-parse --is-shallow-repository)" = false
        test "$(git -C "$scan_dir/repository" rev-parse refs/heads/reviewed)" = "$wrapper_sha"
        scan_history() {
            local label="$1" revision="$2" scan_rc=0
            "$JW_GITLEAKS" git --no-banner --redact --log-opts="$revision" \
                --report-format=json --report-path="$scan_dir/$label.json" "$scan_dir/repository" \
                > "$scan_dir/$label-private.log" 2>&1 || scan_rc=$?
            python -I "$wrapper/scripts/ci_cinema_pg_history_classifier.py" \
                "$scan_dir/$label.json" "$scan_rc" | tee "$evidence/history-$label.log"
        }
        scan_history delta "$remote_base..$wrapper_sha"
        scan_history full --all
        (cd "$wrapper"; python -m pytest -q \
            tests/test_cinema_pg_history_classifier.py tests/test_cinema_pg_history_new_findings.py \
            --junitxml="$evidence/history-classifier.xml") | tee "$evidence/history-classifier.log"
        ;;
    regression)
        # The review database guard permits disposable files under /tmp.
        export TMPDIR="$(mktemp -d /tmp/jw-v223-regression.XXXXXX)"
        export JW_V36_DISPOSABLE_PG17=1
        python -I scripts/jw_v223_pg17_required.py --report "$evidence/pg17-required.xml" | tee "$evidence/pg17-required.log"
        python -m pytest -q -ra --junitxml="$evidence/full.xml" | tee "$evidence/full.log"
        python -m scripts.jw_integrated_acceptance --junit "$evidence/full.xml" | tee "$evidence/integrated-junit.json"
        python - "$evidence/full.xml" <<'PY'
import sys
from xml.etree import ElementTree

cases = list(ElementTree.parse(sys.argv[1]).iter("testcase"))
ids = [(case.get("classname"), case.get("name")) for case in cases]
assert len(ids) == len(set(ids))
assert ids.count(("tests.test_v36_pg17_engine_e2e", "test_real_pg17_engine")) == 1
PY
        node --test --test-concurrency=1 tests/test_*.cjs | tee "$evidence/node.log"
        ;;
    security)
        python -m pytest -q tests/test_jw_v223_{approval,review_preflight,privileged_entry,composite_containment}.py \
            tests/test_v36_shadow_security.py tests/test_cinema_pg_{security_regressions,root_ui_switch,guard}.py \
            tests/test_security*.py --junitxml="$evidence/approval-security.xml" | tee "$evidence/approval-security.log"
        : "${JW_SEMGREP_BIN:?Provide the existing isolated Semgrep installation}"
        PATH="$JW_SEMGREP_BIN:$PATH" SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
            "${JW_SEMGREP_PYTHON:-python}" scripts/ci_semgrep_security.py | tee "$evidence/semgrep.log"
        ;;
    postgres)
        files="$(mktemp -d "$JW_CI_ROOT/pg-files.XXXXXX")"
        socket="$(mktemp -d "$JW_CI_ROOT/pgsocket.XXXXXX")"
        chmod 0777 "$socket"
        cid="$(docker run --pull=never -d --network none \
            -e POSTGRES_PASSWORD=ci-only-v223-preflight -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 \
            -e 'POSTGRES_INITDB_ARGS=--auth-local=trust --auth-host=scram-sha-256' \
            -v "$source_dir:$source_dir:ro" -v "$files:$files:ro" -v "$socket:/jwsocket" \
            postgres:17 -c listen_addresses=127.0.0.1 -c port=5435 \
            -c unix_socket_directories=/var/run/postgresql,/jwsocket)"
        trap 'docker rm -f "$cid" >/dev/null' EXIT
        ready=0
        for attempt in {1..30}; do
            if [[ "$(docker exec "$cid" cat /proc/1/comm)" == postgres ]] && \
                    docker exec "$cid" pg_isready -q -h 127.0.0.1 -p 5435 -U postgres; then
                ready=1
                break
            fi
            sleep 1
        done
        test "$ready" -eq 1
        PGHOST="$socket" PGPORT=5435 PGUSER=postgres PGDATABASE=postgres JW_CINEMA_PG_DISPOSABLE=1 \
            python -I scripts/ci_cinema_pg_p1_p2_pg17_suite.py --report "$evidence/pg17-p1p2.json" | tee "$evidence/pg17-p1p2.log"
        mkdir "$JW_CI_ROOT/pg-bin"
        cat > "$JW_CI_ROOT/pg-bin/psql" <<'WRAPPER'
#!/bin/sh
exec docker exec -i -e PGHOST -e PGPORT -e PGUSER -e PGPASSWORD -e PGOPTIONS -e PGDATABASE "$JW_CI_PG_CONTAINER" psql "$@"
WRAPPER
        chmod 0755 "$JW_CI_ROOT/pg-bin/psql"
        export JW_CI_PG_CONTAINER="$cid"
        export PATH="$JW_CI_ROOT/pg-bin:$PATH"
        export TMPDIR="$files" PGHOST=127.0.0.1 PGPORT=5435 PGUSER=postgres PGDATABASE=postgres
        export PGPASSWORD=ci-only-v223-preflight JW_CINEMA_PG_DISPOSABLE=1
        python scripts/ci_cinema_pg_sql_gate.py --report "$evidence/pg17-engine.json" | tee "$evidence/pg17-engine.log"
        for gate in preflight_gate backup_role_c_gate backup_role_renew_gate 5h_server_gate; do
            python -m "scripts.ci_cinema_pg_v223_$gate" | tee "$evidence/pg17-$gate.log"
        done
        ;;
    browser)
        export JW_ENV=review JW_NO_EXTERNAL_DATABASE=1
        python -m scripts.ci_v223_owner_review_browser | tee "$evidence/browser-owner.log"
        python -m scripts.ci_cinema_pg_v222_root_browser | tee "$evidence/browser-v222.log"
        ;;
    evidence)
        if [[ -d artifacts ]]; then
            cp -a artifacts "$evidence/test-artifacts"
        fi
        cd "$evidence"
        find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
        sha256sum -c SHA256SUMS
        ;;
    *)
        printf '%s\n' 'Use source, history, regression, security, postgres, browser, or evidence.' >&2
        exit 2
        ;;
esac
