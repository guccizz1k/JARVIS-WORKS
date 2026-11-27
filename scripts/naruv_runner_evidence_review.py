"""CI-only capture of actual catalog-checked archive observations.
Never signs a receipt or infers host isolation from a Docker launch argument.
The existing historical runner and aggregate receipt stay unchanged by default.
"""
import hashlib
import os
from scripts import naruv_future_receipt_review as v


def prepare(raw, reference, reference_pin, staged, *, catalog_required, owner_controlled):
    v.need(os.environ.get('GITHUB_ACTIONS')=='true' and
           os.environ.get('GITHUB_REPOSITORY')=='guccizz1k/JARVIS-WORKS' and
           os.environ.get('NARUV_RUNNER_EVIDENCE_CI')=='1','REVIEW_CAPTURE_CI_ONLY')
    v.need(catalog_required is True and owner_controlled is True and
           type(staged) is tuple and len(staged)==4,'REVIEW_CAPTURE_STAGED_OWNER_ONLY')
    doc=v.binding(v.decode(raw))
    v.need(v.canonical(doc)==raw,'REVIEW_BINDING_NOT_CANONICAL')
    manifest,manifest_pin,_,scope=staged
    v.need(type(manifest) is bytes and hashlib.sha256(manifest).hexdigest()==manifest_pin==doc['manifest_sha256'],'REVIEW_MANIFEST_PIN_MISMATCH')
    v.need(type(reference) is bytes and hashlib.sha256(reference).hexdigest()==reference_pin==doc['reference_sha256'],'REVIEW_REFERENCE_PIN_MISMATCH')
    v.need(scope==doc['scope'],'REVIEW_SCOPE_MISMATCH')
    v.need(os.environ.get('NARUV_EXPECTED_RUNNER_SHA')==doc['runner_commit'],'REVIEW_RUNNER_PIN_MISMATCH')
    # Immutable approved bytes, not a mutable dict shared with the caller.
    return raw


def check_archive_set(capture,pairs):
    expected=v.binding(v.decode(capture))['archives']
    v.need(len(pairs)==11 and sorted(h for _,h in pairs)==expected,'REVIEW_ARCHIVE_SET_MISMATCH')


def finish(capture,observed,report):
    blocked={'status':'BLOCKED','archive_results':[],
             'host_isolation':'NOT_ATTESTED','signature':'NOT_CREATED','production_authorized':False}
    doc=v.binding(v.decode(capture))
    if not (report.get('owner_site_restore')=='PASS_ELEVEN_OWNER_SITE_CIPHERS' and
            report.get('normalized_catalog_comparison')=='PASS_11_SCOPED_CATALOG_CHECKPOINTS' and
            report.get('normalized_archive_comparison')=='PASS_11_ARCHIVE_CHECKPOINTS' and
            report.get('disposable_pg17_removed')=='PASS' and
            report.get('review_cleanup_absence_verified') is True and
            report.get('b2_staged_scope_bound') is True and
            report.get('owner_scope_pin_checked') is True and
            report.get('decrypted_dump_written_to_host') is False and
            all(type(report.get(k)) is int and report[k]==11 for k in
                ('verified_provider_cipher_count','restored_pg17_archive_count','restored_65_table_archive_count')) and
            type(report.get('restore_failures')) is int and report['restore_failures']==0 and
            len(observed)==11 and sorted(observed)==doc['archives']):
        return blocked
    return {'status':'PASS_ARCHIVE_OBSERVATIONS_ONLY',
            'binding_sha256':hashlib.sha256(capture).hexdigest(),
            'archive_results':[dict(archive_sha256=h,authenticated=True,restored=True,rows_match=True,catalog_match=True) for h in doc['archives']],
            'host_isolation':'NOT_ATTESTED','signature':'NOT_CREATED','production_authorized':False}
