"""V17.3 strict additive index contract for five observed DEV FK warnings.

All 26+ corruptions must invalidate the contract before any DEV migration.
Actual SQL migration is independently executed in real DEV inside ROLLBACK.
"""
from pathlib import Path
import re
import pytest

SQL=(Path(__file__).resolve().parents[1]/"scripts/review/v173_dev_approval_fk_indexes.sql").read_text()

INDEXES={
 "jw_v173_idx_draft_item_quote_fk":("order_draft_items_v127","source_quote_item_id"),
 "jw_v173_idx_draft_customer_fk":("order_drafts_v127","customer_id"),
 "jw_v173_idx_draft_quote_fk":("order_drafts_v127","quote_id"),
 "jw_v173_idx_receipt_org_fk":("quote_review_receipts_v128","org_id"),
 "jw_v173_idx_receipt_quote_fk":("quote_review_receipts_v128","quote_id"),
}
GUARDS=[
 "BEGIN;",
 "SET LOCAL lock_timeout='1200ms';",
 "SET LOCAL statement_timeout='20s';",
 "current_database()<>'postgres'",
 "current_user<>'postgres'",
 "forced<>43",
 "policies<>62",
 "OR EXISTS(SELECT 1 FROM jw_dev.organizations)",
 "OR EXISTS(SELECT 1 FROM jw_dev.users)",
 "OR EXISTS(SELECT 1 FROM jw_dev.sessions)",
 "OR EXISTS(SELECT 1 FROM jw_dev.order_drafts_v127)",
 "OR EXISTS(SELECT 1 FROM jw_dev.order_draft_items_v127)",
 "OR EXISTS(SELECT 1 FROM jw_dev.quote_review_receipts_v128)",
 "OR to_regclass('jw_dev.jw_v173_idx_draft_item_quote_fk') IS NOT NULL",
 "OR to_regclass('jw_dev.jw_v173_idx_draft_customer_fk') IS NOT NULL",
 "OR to_regclass('jw_dev.jw_v173_idx_draft_quote_fk') IS NOT NULL",
 "OR to_regclass('jw_dev.jw_v173_idx_receipt_org_fk') IS NOT NULL",
 "OR to_regclass('jw_dev.jw_v173_idx_receipt_quote_fk') IS NOT NULL",
 "V173_DEV_ONLY_EMPTY_APPROVAL_TABLE_GUARD",
 "IF indexed<>5 OR invalid<>0 OR forced<>43 OR policies<>62",
 "NOT ix.indisvalid OR NOT ix.indisready",
 "V173_INDEX_OR_SECURITY_POSTCONDITION_FAIL",
 "COMMIT;",
 "PASS_V173_ONLY_FIVE_NEW_DEV_FK_INDEXES",
]

def _contract(s):
    if not all(g in s for g in GUARDS):
        return False
    if s.count("forced<>43")!=2 or s.count("policies<>62")!=2:
        return False
    if s.count("CREATE INDEX ")!=5:
        return False
    if any(re.search(p,s,re.I) for p in [
        r"\bDROP\b",r"\bTRUNCATE\b",r"\bDELETE FROM\b",
        r"\bALTER TABLE\b",r"\bGRANT\b",r"\bREVOKE\b",
        r"\bINSERT INTO\b",r"\bUPDATE jw_dev\b",
        r"\bSECURITY DEFINER\b",r"\bDISABLE ROW LEVEL SECURITY\b",
    ]):
        return False
    for name,(table,column) in INDEXES.items():
        regex=(r"(?m)^CREATE INDEX "+re.escape(name)+r"\s*"
               +r"ON jw_dev\."+re.escape(table)+r"\s*"
               +r"\("+re.escape(column)+r"\);")
        if not re.search(regex,s):
            return False
    return True


def test_index_contract_fixes_only_five_observed_foreign_key_gap():
    assert _contract(SQL)
    assert not any(x in SQL for x in ("CREATE INDEX CONCURRENTLY",
                                      "CREATE UNIQUE INDEX","IF NOT EXISTS"))
    assert all("jw_v173_idx_" in name for name in INDEXES)
    assert SQL.count("FORCE ROW LEVEL SECURITY")==0
    assert SQL.count("CREATE POLICY")==0


_MUTATIONS=[
 ("BEGIN;",""),
 ("SET LOCAL lock_timeout='1200ms';","SET LOCAL lock_timeouts='1200ms';"),
 ("SET LOCAL statement_timeout='20s';","SET LOCAL statement_timeout='200s';"),
 ("current_database()<>'postgres'","false"),
 ("current_user<>'postgres'","false"),
 ("forced<>43","forced<>44"),
 ("policies<>62","policies<>63"),
 ("OR EXISTS(SELECT 1 FROM jw_dev.organizations)",""),
 ("OR EXISTS(SELECT 1 FROM jw_dev.users)",""),
 ("OR EXISTS(SELECT 1 FROM jw_dev.sessions)",""),
 ("OR EXISTS(SELECT 1 FROM jw_dev.order_drafts_v127)",""),
 ("OR EXISTS(SELECT 1 FROM jw_dev.order_draft_items_v127)",""),
 ("OR EXISTS(SELECT 1 FROM jw_dev.quote_review_receipts_v128)",""),
 ("OR to_regclass('jw_dev.jw_v173_idx_draft_item_quote_fk') IS NOT NULL",""),
 ("OR to_regclass('jw_dev.jw_v173_idx_draft_customer_fk') IS NOT NULL",""),
 ("OR to_regclass('jw_dev.jw_v173_idx_draft_quote_fk') IS NOT NULL",""),
 ("OR to_regclass('jw_dev.jw_v173_idx_receipt_org_fk') IS NOT NULL",""),
 ("OR to_regclass('jw_dev.jw_v173_idx_receipt_quote_fk') IS NOT NULL",""),
 ("CREATE INDEX jw_v173_idx_draft_item_quote_fk","CREATE INDEX idx_wrong"),
 ("CREATE INDEX jw_v173_idx_draft_customer_fk","CREATE INDEX idx_wrong"),
 ("CREATE INDEX jw_v173_idx_draft_quote_fk","CREATE INDEX idx_wrong"),
 ("CREATE INDEX jw_v173_idx_receipt_org_fk","CREATE INDEX idx_wrong"),
 ("CREATE INDEX jw_v173_idx_receipt_quote_fk","CREATE INDEX idx_wrong"),
 ("IF indexed<>5 OR invalid<>0 OR forced<>43 OR policies<>62","IF indexed<>4 OR invalid<>0 OR forced<>43 OR policies<>62"),
 ("NOT ix.indisvalid OR NOT ix.indisready","false"),
 ("V173_INDEX_OR_SECURITY_POSTCONDITION_FAIL","ignored"),
 ("COMMIT;","ROLLBACK;"),
 ("PASS_V173_ONLY_FIVE_NEW_DEV_FK_INDEXES","unsafe"),
]

@pytest.mark.parametrize(("before","after"),_MUTATIONS,
 ids=[f"corrupt-{i:02}" for i in range(1,len(_MUTATIONS)+1)])
def test_independent_guard_corruption_cannot_pass_contract(before,after):
    assert before in SQL
    damaged=SQL.replace(before,after,1)
    assert damaged!=SQL and not _contract(damaged)
