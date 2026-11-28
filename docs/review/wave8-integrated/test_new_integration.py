"""New Wave8 cross-module integration, not repeat of prior unit tests.
No live provider, real backup, production credentials, or statutory authorization.
"""
import copy, hashlib, importlib.util, io, os, tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from functools import partial
import pytest
from reportlab.pdfgen import canvas
from openpyxl import Workbook
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from app.naruv_kr_payroll_review import fixed_week_wage_statement_draft_2026 as statement, verify_fixed_week_statement_source_2026 as verify, PayrollBlocked
from app.naruv_operational_readiness import review_and_consume_local_challenge, custody_trust_pin
from app.naruv_document_review import review_document
from app.erp_migration_xlsx import parse_xlsx
from handoff import stable_ops, payroll_handoff, custody_handoff
from pinned.naruv_recovery_custody_review import custody_evidence_message
from bounded_pdf import pdf_review
from document_candidates import review_candidates
from review_gates import Blocked
from test_https_local import local_tls
import qa_probe

def sha(b):return hashlib.sha256(b).hexdigest()

def test_real_tls_receipt_bracket(local_tls,monkeypatch):
    monkeypatch.setenv('CURL_CA_BUNDLE',str(local_tls))
    before=dict(service='srv-fixture',deploy='dep-fixture',sha='a'*40,live=True,observed_at=datetime.now(timezone.utc))
    started=datetime.now(timezone.utc)
    probe=qa_probe.assess(budget=10)
    ended=datetime.now(timezone.utc)
    after=dict(before,observed_at=datetime.now(timezone.utc))
    a=dict(expected_service=before['service'],expected_deploy=before['deploy'],expected_sha=before['sha'],before=before,after=after,probe=probe,started=started,ended=ended,now=datetime.now(timezone.utc))
    r=stable_ops(**a)
    assert r['status']=='BRACKETED_METADATA_AND_TRANSPORT_ONLY',r
    assert not r['served_sha_verified'] and not r['provider_authenticated'] and not r['production_authorized']
    assert stable_ops(**dict(a,after=dict(after,deploy='changed')))['status']=='BLOCKED_EVIDENCE'
    print('WAVE8_LOCAL_TLS_BRACKET_PASS')

def paid_fixture():
    p=Path(os.environ['WAVE2_DIR'])/'test_paid_statement.py'
    spec=importlib.util.spec_from_file_location('paid_fixture',p)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m.PaidStatement().fixture()

@pytest.mark.parametrize('early',[False,True])
def test_actual_payroll_handoff(early,tmp_path):
    a=paid_fixture()
    if early:a['payment_date']='2026-11-01'
    # Simulated independent prior record from a separate generation, not live payroll DB.
    previous=statement(**copy.deepcopy(a))
    trusted=dict(tenant=a['tenant'],worker=a['worker'],period=a['period'],
        assessment_sha256=a['completeness_assessment_sha256'],expected_review_sha256=previous['review_sha256'],
        expected_monthly_review_sha256=previous['source_review_sha256'])
    import json
    pin=tmp_path/'prior.json';pin.write_text(json.dumps(trusted))
    current=statement(**a)
    kw=dict(draft=current,trusted=json.loads(pin.read_text()),confirmed_days=[r['date'] for r in a['minutes_by_day']],verifier=verify)
    r=payroll_handoff(**kw)
    assert r['source_integrity_verified'] and not r['payment_authorized'] and not r['statutory_validated']
    assert r['issues']==(['PROPOSED_DATE_PRECEDES_CONFIRMED_WORK'] if early else [])
    forged=copy.deepcopy(current);forged['gross_krw']+=1;forged['net_krw']+=1
    with pytest.raises(PayrollBlocked):payroll_handoff(**dict(kw,draft=forged))
    print('WAVE8_ACTUAL_PAYROLL_VERIFIER_HANDOFF_PASS')

def test_real_custody_journal_order_and_replay():
    ik,ck=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
    ip,cp=[k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw) for k in (ik,ck)]
    keys={'k1':dict(state='ACTIVE',expected_assets={'a':'a'*64}),'k2':dict(state='RECOVERY_ONLY',expected_assets={'b':'b'*64})}
    obs=[dict(key_id=k,state=v['state'],site_id='site2',custody_receipt_sha256='c'*64,restores=[dict(asset_id=a,ciphertext_sha256=h,restore_evidence_sha256='d'*64,full_authentication=True,restore_ok=True,network_isolated=True) for a,h in v['expected_assets'].items()]) for k,v in keys.items()]
    args=dict(tenant='tenant',expected_keys=keys,observations=obs,trust=dict(primary_site='site1',independent_site='site2',inventory_fingerprint=sha(ip),custodian_fingerprint=sha(cp)),challenge='e'*64,issued_at=datetime.now(timezone.utc))
    msg=custody_evidence_message(**args)
    evidence=dict(args,inventory_public_key=ip,custodian_public_key=cp,inventory_signature=ik.sign(b'inventory:'+msg),custodian_signature=ck.sign(b'custodian:'+msg))
    expected={'k1/a':'a'*64,'k2/b':'b'*64}
    rows=[dict(asset_id=k,ciphertext_sha256=v,version_id=str(i)) for i,(k,v) in enumerate(expected.items())]
    with tempfile.TemporaryDirectory(prefix='wave8-journal-',dir='/tmp') as d:
        kw=dict(evidence=evidence,expected_trust_pin=custody_trust_pin(tenant=args['tenant'],expected_keys=keys,trust=args['trust']),expected_challenge=args['challenge'],expected=expected,vault=copy.deepcopy(rows),b2=copy.deepcopy(rows),consume=partial(review_and_consume_local_challenge,journal_dir=d))
        invalid=copy.deepcopy(rows);invalid[0]['ciphertext_sha256']='f'*64
        with pytest.raises(Blocked,match='RESTORE_DIGEST'):custody_handoff(**dict(kw,b2=invalid))
        assert list(Path(d).iterdir())==[]
        r=custody_handoff(**kw)
        assert r['local_challenge_consumed'] and r['asset_count']==2 and not r['physical_custody_verified'] and not r['production_authorized']
        files=list(Path(d).iterdir());assert len(files)==1 and files[0].stat().st_mode & 0o777==0o600
        old=files[0].read_bytes()
        with pytest.raises(ValueError,match='CUSTODY_LOCAL_REPLAY'):custody_handoff(**kw)
        assert files[0].read_bytes()==old
    print('WAVE8_REAL_LOCAL_JOURNAL_SEQUENCE_PASS')

VALUES={'document_kind':'invoice','counterparty_id':'C001','document_date':'2026-11-28','reference_number':'001','subtotal':'1000','vat':'100','gross_amount':'1100'}
@pytest.mark.parametrize('conflict',[False,True])
def test_multipage_pdf_worker_equivalence(conflict):
    f=io.BytesIO();c=canvas.Canvas(f)
    pairs=list(VALUES.items())
    for page in (pairs[:4],pairs[4:]+([('gross_amount','1200')] if conflict else [])):
        t=c.beginText(50,750)
        for k,v in page:t.textLine(f'{k}: {v}')
        c.drawText(t);c.showPage()
    c.save();raw=f.getvalue();h=sha(raw)
    actual=pdf_review(raw=raw,registered=h,tenant='tenant')
    direct=review_candidates(tenant='tenant',raw=raw,registered=h,format='pdf',review_document=review_document)
    assert actual==direct and not actual['posting_authorized']
    assert ('CONFLICT_GROSS_AMOUNT' in actual['issues'])==conflict
    print('WAVE8_MULTIPAGE_PDF_WORKER_EQUIVALENCE_PASS')

def test_pdf_page_bound():
    f=io.BytesIO();c=canvas.Canvas(f)
    for _ in range(21):
        c.drawString(50,750,'document_kind: invoice');c.showPage()
    c.save();raw=f.getvalue()
    with pytest.raises(Blocked,match='DOC_PAGE_LIMIT'):pdf_review(raw=raw,registered=sha(raw),tenant='tenant')

def test_assembled_xlsx_conflict_with_original_review():
    f=io.BytesIO();w=Workbook();w.active.append(['field','value'])
    for k,v in VALUES.items():w.active.append([k,v])
    w.active.append(['gross_amount','1200']);w.save(f);w.close()
    raw=f.getvalue()
    r=review_candidates(tenant='tenant',raw=raw,registered=sha(raw),format='xlsx',review_document=review_document,strict_parser=parse_xlsx)
    assert r['issues']==['CONFLICT_GROSS_AMOUNT'] and not r['posting_authorized']
    print('WAVE8_ASSEMBLED_XLSX_REVIEW_PASS')
