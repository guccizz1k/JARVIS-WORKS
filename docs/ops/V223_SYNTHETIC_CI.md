# V22.3 PG17 isolated CI acceptance

The `jw-cinema-pg-v223-backup-qa.yml` workflow runs the unchanged approved
application (base SHA `864054f1`) plus the V22.3 review-only backup tools.
It uses two fresh, separate PostgreSQL 17 service containers. It tests a
synthetic schema with two tables, RLS, a policy, a function and a trigger.

The test asserts: source signature and dump use one exported PostgreSQL snapshot;
AES-256-GCM round-trip; encrypted tamper/wrong-key/truncation rejection;
real `pg_restore` rejection of a cut-off archive; restored signature match;
no customer credentials and no real Supabase connection.

It also runs the V22.3 hotfix negative tests on the real clusters: the restore target is
refused with a wrong marker token, as an unmarked cluster, and while a foreign database exists
(and nothing is created on a refused target); source roles that are superuser, writable,
schema-creating or unable to read all RLS rows are refused while a read-only BYPASSRLS role is
accepted; the signature digest ignores physical row order, changes when one value changes, and
stops on an exact per-table row cap or a statement timeout.

`PASS_V223_SYNTHETIC_DOUBLE_PG17...` is **NOT** P0-1 real-data PASS.
Real Supabase P0-1 requires an approved read-only source role, verified TLS,
actual encrypted backup, *separate* restored PG17, full data/RLS/ACL comparison,
source identity evidence, and protection of the actual existing development DB.

The original CINEMA assets, legacy workflows and production/Render are unchanged.
