"""S4 historical reconciliation regression: no implicit links or live data.

The test fixture invents all data. Publication remains BLOCKED even after an
internally consistent manual-review candidate; trusted server signature and
stored approval are a separate, currently unavailable gate.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from app.pg_cinema_s4_reconciliation_v1 import (
    Line, Quote, ReviewedLink, approved_unique_subtotal,
    audit_links, digest, provisional_unique_subtotal,
)


def records():
    old = Quote("v92", "org-a", "old-q-01", "Q-2026-ABC", "123-45-67890",
                "taxable", "approved",
                (Line("Part A", 5, 3501), Line("Part B", 2, 1000)))
    new = Quote("cinema", "org-a", "new-q-01", "T261105-0001", "1234567890",
                "taxable", "ordered",
                (Line("Part B", 2, 1000), Line("Part A", 5, 3501)))
    return old, new


def reviewed(old, new, **kwargs):
    link = ReviewedLink("org-a", old.quote_id, new.quote_id, "reviewer-01",
                        "independent-evidence-ref-00001", digest(old), digest(new))
    return replace(link, **kwargs)


def assert_finding(audit, code):
    assert code in {x.code for x in audit.findings}


def test_identical_lines_different_orders_are_consistent_proposals():
    old, new = records()
    report = audit_links((old,), (new,), (reviewed(old,new),))
    assert report.consistent_for_manual_review
    assert not report.publishable
    assert len(report.accepted) == 1 and not report.findings
    assert provisional_unique_subtotal(report, (new,)) == 19505
    with pytest.raises(ValueError, match="authenticated server-side"):
        approved_unique_subtotal(report, (new,))


def test_zero_links_never_inferred_from_matching_business_number_and_amount():
    old,new=records()
    result=audit_links((old,),(new,),())
    assert not result.consistent_for_manual_review and not result.publishable
    assert result.unlinked_legacy and result.unlinked_cinema
    with pytest.raises(ValueError,match="BLOCKED"):
        provisional_unique_subtotal(result,(new,))


@pytest.mark.parametrize("attribute,value,issue", [
    ("vat_mode","exempt","VAT_MISMATCH"),
    ("business_number","9999999999","COUNTERPARTY_MISMATCH"),
    ("lines",(Line("Part B",2,1000),Line("Part A",4,3501)),"ITEM_MISMATCH"),
    ("lines",(Line("Part B",2,1000),Line("Part A",5,3502)),"ITEM_MISMATCH"),
    ("lines",(Line("Part B",2,1000),Line("Part A",5,3501),
              Line("Part A",5,3501)),"ITEM_MISMATCH"),
    ("status","cancelled","STATUS_MISMATCH"),
    ("status","reversed","STATUS_MISMATCH"),
])
def test_mismatched_business_data_never_links(attribute,value,issue):
    old,new=records()
    new=replace(new,**{attribute:value})
    result=audit_links((old,),(new,),(reviewed(old,new),))
    assert_finding(result,issue)
    assert not result.accepted and not result.publishable
    assert result.unlinked_legacy and result.unlinked_cinema


@pytest.mark.parametrize("attribute,value",[
    ("quantity",True),("quantity",0),("quantity",-1),
    ("quantity",100001),("quantity",1.0),
    ("unit_price",True),("unit_price",-1),
    ("unit_price",1000000001),("unit_price",1.0),
    ("name"," "),("name","  Part A"),("name","Part A  "),
    ("name","X"*151),
])
def test_bad_line_data_is_not_accepted(attribute,value):
    old,new=records()
    new=replace(new,lines=(replace(new.lines[0],**{attribute:value}),new.lines[1]))
    result=audit_links((old,),(new,),())
    assert_finding(result,"INVALID_SNAPSHOT")
    assert not result.publishable


@pytest.mark.parametrize("attribute,value",[
    ("business_number",""),("business_number","١٢٣٤٥٦٧٨٩٠"),
    ("business_number","123456789"),("business_number","12345678901"),
    ("vat_mode","unknown"),("org_id","  "),("org_id"," bad "),
    ("doc_no"," "),("status",""),
])
def test_invalid_identifiers_cannot_be_mapped(attribute,value):
    old,new=records()
    new=replace(new,**{attribute:value})
    report=audit_links((old,),(new,),())
    assert_finding(report,"INVALID_SNAPSHOT")
    assert not report.consistent_for_manual_review


def test_cross_tenant_quote_id_fails_closed():
    old,new=records()
    new=replace(new,org_id="org-b")
    link=ReviewedLink("org-a",old.quote_id,new.quote_id,"reviewer-01",
                      "reference-000001",digest(old),digest(new))
    report=audit_links((old,),(new,),(link,))
    assert_finding(report,"MISSING_SOURCE")
    assert not report.publishable


@pytest.mark.parametrize("attribute,value",[
    ("reviewer_id",""),("review_reference","short"),
    ("org_id",""),("review_reference",""),
])
def test_missing_human_review_metadata_blocked(attribute,value):
    old,new=records()
    link=replace(reviewed(old,new),**{attribute:value})
    report=audit_links((old,),(new,),(link,))
    assert_finding(report,"MISSING_REVIEW")
    assert not report.accepted


def test_stale_legacy_digest_blocks_link():
    old,new=records()
    link=replace(reviewed(old,new),legacy_digest="0"*64)
    report=audit_links((old,),(new,),(link,))
    assert_finding(report,"STALE_REVIEW")
    assert not report.accepted


def test_stale_cinema_digest_blocks_link():
    old,new=records()
    link=replace(reviewed(old,new),cinema_digest="0"*64)
    report=audit_links((old,),(new,),(link,))
    assert_finding(report,"STALE_REVIEW")


def test_one_to_many_link_is_rejected():
    old,new=records()
    next_new=replace(new,quote_id="new-q-02",doc_no="T261105-0002")
    result=audit_links((old,),(new,next_new),
                       (reviewed(old,new),reviewed(old,next_new)))
    assert_finding(result,"NON_BIJECTIVE")
    assert not result.publishable


def test_many_to_one_link_is_rejected():
    old,new=records()
    second=replace(old,quote_id="old-q-02",doc_no="Q-2026-DEF")
    result=audit_links((old,second),(new,),
                       (reviewed(old,new),reviewed(second,new)))
    assert_finding(result,"NON_BIJECTIVE")
    assert not result.publishable


def test_duplicate_source_snapshot_never_publishable():
    old,new=records()
    report=audit_links((old,old),(new,),(reviewed(old,new),))
    assert_finding(report,"DUPLICATE_SNAPSHOT")
    assert not report.publishable


def test_wrong_ledger_snapshot_refused():
    old,new=records()
    report=audit_links((new,),(old,),())
    assert_finding(report,"LEDGER_MISMATCH")


def test_unlinked_second_quote_blocks_provisional_total():
    old,new=records()
    second=replace(old,quote_id="old-q-02")
    report=audit_links((old,second),(new,),(reviewed(old,new),))
    assert report.unlinked_legacy==("org-a:old-q-02",)
    assert not report.consistent_for_manual_review
    with pytest.raises(ValueError,match="BLOCKED"):
        provisional_unique_subtotal(report,(new,))


@pytest.mark.parametrize("state",["draft","submitted","cancelled","rejected"])
def test_draft_and_void_quotes_never_count_as_reportable(state):
    old,new=records()
    old=replace(old,status=state)
    new=replace(new,status=state)
    report=audit_links((old,),(new,),(reviewed(old,new),))
    assert report.accepted
    assert not report.consistent_for_manual_review
    with pytest.raises(ValueError,match="BLOCKED"):
        provisional_unique_subtotal(report,(new,))


def test_tenant_identifiers_are_part_of_digest():
    old,new=records()
    assert digest(old)!=digest(replace(old,org_id="org-b"))
    assert digest(new)!=digest(replace(new,org_id="org-b"))


def test_document_ids_are_part_of_digest_no_guessing_by_date_or_amount():
    old,new=records()
    assert digest(old)!=digest(replace(old,doc_no="Q-OTHER"))
    assert digest(new)!=digest(replace(new,quote_id="new-other"))


def test_legitimate_second_tenant_review_is_independent():
    old,new=records()
    old_b=replace(old,org_id="org-b",quote_id="old-b")
    new_b=replace(new,org_id="org-b",quote_id="new-b")
    old_link=reviewed(old,new)
    new_link=replace(reviewed(old_b,new_b),org_id="org-b")
    report=audit_links((old,old_b),(new,new_b),(old_link,new_link))
    assert len(report.accepted)==2 and report.consistent_for_manual_review
    assert provisional_unique_subtotal(report,(new,new_b))==39010
    assert not report.publishable
