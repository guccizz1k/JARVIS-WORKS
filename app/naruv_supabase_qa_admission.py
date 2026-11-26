"""Provider-specific admission for a fresh, dedicated Supabase QA project.
No connection, migration, credentials, or production release on import.
Trusted provider metadata and catalog results must be obtained by the caller.
A successful preflight authorizes neither copying CI-only SQL nor deployment.
"""
import re
from .naruv_hosted_qa_admission import need

QA_REF="scvqtsyxkqddoorcaiqr"
QA_ORG="wqxhqvyarabbjnkgsrol"
QA_NAME="naruv-one-isolated-qa"
PROBE_VERSION="20261126000557"
PROBE_NAME="naruv_qa_private_readonly_fixture"

def verify_provider_project(project, *, expected_sha, migrations, catalog, rollback):
    need(type(expected_sha) is str and re.fullmatch(r"[0-9a-f]{40}",expected_sha),"SUPABASE_SOURCE_SHA")
    need(type(project) is dict and project.get("id")==QA_REF and project.get("ref")==QA_REF
        and project.get("organization_id")==QA_ORG and project.get("name")==QA_NAME
        and project.get("region")=="ap-northeast-2" and project.get("status")=="ACTIVE_HEALTHY",
        "SUPABASE_PROJECT_SCOPE")
    db=project.get("database")
    need(type(db) is dict and db.get("host")=="db."+QA_REF+".supabase.co"
        and db.get("postgres_engine")=="17","SUPABASE_PROJECT_ENGINE")
    need(type(migrations) is list and len(migrations)==1 and type(migrations[0]) is dict
        and migrations[0].get("version")==PROBE_VERSION and migrations[0].get("name")==PROBE_NAME,
        "SUPABASE_MIGRATION_DRIFT")
    expected={"current_user":"postgres","session_user":"postgres","current_database":"postgres",
        "superuser":False,"createrole":True,"bypassrls":True,"existing_erp_schemas":0,"conflicting_roles":0}
    need(type(catalog) is dict and set(catalog)==set(expected)|{"version_num"}
        and all(type(catalog[k]) is type(v) and catalog[k]==v for k,v in expected.items())
        and type(catalog["version_num"]) is int and 170000<=catalog["version_num"]<180000,
        "SUPABASE_CATALOG_SCOPE")
    need(type(rollback) is dict and set(rollback)=={"schema_rolled_back","roles_rolled_back","original_fixture_intact"}
        and all(x is True for x in rollback.values()),"SUPABASE_REHEARSAL_ROLLBACK")
    return {"status":"DEDICATED_MANAGED_DB_PREFLIGHT_ONLY","source_sha":expected_sha,
        "requires_hosted_schema_review":True,"runtime_credentials_verified":False,
        "migration_authorized":False,"deployment_authorized":False,"production_authorized":False}

def require_hosted_sql_source(path, text):
    """Deny raw CI fixture install, including files with explicit provider ban.
    No translation, no setting CI-only acknowledgements on hosted database.
    """
    need(type(path) is str and type(text) is str,"SUPABASE_SQL_SOURCE")
    need(path.startswith("db/review/naruv_supabase_hosted_") and path.endswith(".sql")
        and re.fullmatch(r"db/review/naruv_supabase_hosted_[a-z0-9_]+\.sql",path),
        "SUPABASE_SQL_NOT_HOSTED_CANDIDATE")
    upper=text.upper()
    need(not any(x in upper for x in ("DISPOSABLE_ONLY","NEVER MIGRATE ONTO SUPABASE",
        "ALTER SYSTEM","CREATE EXTENSION","DROP DATABASE","DROP SCHEMA","\\CONNECT")),
        "SUPABASE_SQL_SCOPE_REFUSED")
    # Naming and text screening are necessary but not sufficient for approval.
    return {"status":"SOURCE_SCREEN_ONLY","migration_authorized":False}
