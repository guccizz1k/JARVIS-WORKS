"""Review-only composition of trusted acquisitions and existing verifiers.
No legal, payment, custody, production or deployment approval is issued.
"""
from datetime import date, datetime, timedelta, timezone
from copy import deepcopy
import hashlib
import re
from review_gates import Blocked, need, digest, utc, operations_gate, reconcile_restore_inventory
from pinned.naruv_recovery_custody_review import custody_evidence_message, review_custody_evidence, canonical


def stable_ops(*, expected_service, expected_deploy, expected_sha, before, after, probe, started, ended, now):
    """Bracket a probe with independently acquired provider snapshots. No network proof."""
    for x in (expected_service, expected_deploy):
        need(type(x) is str and re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',x),'OPS_ID')
    need(digest(expected_sha,40) and all(utc(x) for x in (started,ended,now)),'OPS_SHAPE')
    need(started<=ended<=now and ended-started<=timedelta(seconds=120),'OPS_WINDOW')
    reasons=[]
    fields={'service','deploy','sha','live','observed_at'}
    for snap in (before,after):
        need(type(snap) is dict and set(snap)==fields and utc(snap['observed_at']) and type(snap['live']) is bool,'OPS_METADATA')
        if (snap['service'],snap['deploy'],snap['sha'],snap['live'])!=(expected_service,expected_deploy,expected_sha,True):reasons.append('OPS_DEPLOYMENT_MISMATCH')
    if not before['observed_at']<=started<=ended<=after['observed_at']<=now:reasons.append('OPS_BRACKET_ORDER')
    if not timedelta(0)<=now-before['observed_at']<=timedelta(minutes=5):reasons.append('OPS_BRACKET_STALE')
    r=operations_gate(expected_sha=expected_sha,observed_sha=after['sha'],observed_at=after['observed_at'],now=now,probe=probe,deployment_live=after['live'])
    reasons=sorted(set(reasons+r['reasons']))
    return dict(status='BLOCKED_EVIDENCE' if reasons else 'BRACKETED_METADATA_AND_TRANSPORT_ONLY',reasons=reasons,provider_authenticated=False,served_sha_verified=False,authenticated_business_verified=False,production_authorized=False)


def payroll_handoff(*, draft, trusted, confirmed_days, verifier):
    """Require a separately acquired prior digest, not the draft's self-declared digest.
    A date before covered work is flagged for human review, not a legal conclusion.
    Trusted records and confirmed_days must come from authenticated server-side storage.
    """
    keys={'tenant','worker','period','assessment_sha256','expected_review_sha256','expected_monthly_review_sha256'}
    need(type(trusted) is dict and set(trusted)==keys and type(draft) is dict,'HR_HANDOFF_SHAPE')
    need(all(type(trusted[k]) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}',trusted[k]) for k in ('tenant','worker')),'HR_HANDOFF_SCOPE')
    need(type(trusted['period']) is str and re.fullmatch(r'2026-(0[1-9]|1[0-2])',trusted['period']),'HR_HANDOFF_SCOPE')
    need(all(digest(trusted[k]) for k in keys if k.endswith('sha256')),'HR_HANDOFF_PIN')
    need((draft.get('worker'),draft.get('period'),draft.get('source_review_sha256'))==(trusted['worker'],trusted['period'],trusted['expected_monthly_review_sha256']),'HR_HANDOFF_SOURCE')
    result=verifier(draft=draft,tenant=trusted['tenant'],assessment_sha256=trusted['assessment_sha256'],expected_review_sha256=trusted['expected_review_sha256'])
    need(type(result) is dict and result.get('status')=='DRAFT_SOURCE_INTEGRITY_ONLY' and all(result.get(k) is False for k in ('statutory_validated','payment_authorized','delivery_authorized','production_authorized')),'HR_HANDOFF_VERIFIER')
    need(type(confirmed_days) is list and 1<=len(confirmed_days)<=31,'HR_HANDOFF_DAYS')
    seen=set(); dates=[]
    try:
        for day in confirmed_days:
            need(type(day) is str and day.startswith(trusted['period']+'-'),'HR_HANDOFF_DAYS')
            dt=date.fromisoformat(day);need(dt.isoformat()==day and dt not in seen,'HR_HANDOFF_DAYS');seen.add(dt);dates.append(dt)
        raw=draft.get('proposed_payment_date');need(type(raw) is str,'HR_HANDOFF_DATE');payment=date.fromisoformat(raw);need(payment.isoformat()==raw,'HR_HANDOFF_DATE')
    except (ValueError,TypeError):raise Blocked('HR_HANDOFF_DATE_OR_DAYS') from None
    return dict(status='DRAFT_HANDOFF_REVIEW_ONLY',issues=['PROPOSED_DATE_PRECEDES_CONFIRMED_WORK'] if payment<max(dates) else [],source_integrity_verified=True,completeness_verified=False,statutory_validated=False,payment_authorized=False,delivery_authorized=False,production_authorized=False)


def custody_handoff(*, evidence, expected_trust_pin, expected_challenge, expected, vault, b2, consume):
    """Authenticate signed claims and match inventories BEFORE consuming challenge.
    consume is the existing owner-local journal verifier; no remote IO here.
    Provider snapshots remain caller-authenticated inputs, not attested by this function.
    """
    e=deepcopy(evidence); exp=deepcopy(expected); va=deepcopy(vault); bb=deepcopy(b2)
    need(type(e) is dict and set(e)=={'tenant','expected_keys','observations','trust','challenge','issued_at','inventory_public_key','custodian_public_key','inventory_signature','custodian_signature'},'RESTORE_EVIDENCE_SHAPE')
    need(digest(expected_challenge) and e['challenge']==expected_challenge and digest(expected_trust_pin),'RESTORE_CHALLENGE')
    pin=hashlib.sha256(canonical(['NARUV_CUSTODY_TRUST_PIN_V1',e['tenant'],e['expected_keys'],e['trust']])).hexdigest()
    need(pin==expected_trust_pin,'RESTORE_TRUST_PIN')
    msg=custody_evidence_message(**{k:e[k] for k in ('tenant','expected_keys','observations','trust','challenge','issued_at')})
    checked=review_custody_evidence(**e,as_of=datetime.now(timezone.utc))
    result=reconcile_restore_inventory(expected=exp,vault=va,b2=bb,signed_review=checked,trusted_evidence_sha256=checked['evidence_sha256'],signed_message=msg)
    consumed=consume(expected_trust_pin=expected_trust_pin,expected_challenge=expected_challenge,**deepcopy(e))
    need(type(consumed) is dict and consumed.get('status')==checked['status'] and consumed.get('evidence_sha256')==checked['evidence_sha256'] and consumed.get('local_challenge_consumed') is True and consumed.get('distributed_challenge_consumption_verified') is False and all(consumed.get(k) is False for k in ('physical_custody_verified','independent_site_verified','key_activation_authorized','key_retirement_authorized','deletion_authorized','production_authorized')),'RESTORE_CONSUMPTION_UNVERIFIED')
    return dict(result,status='INVENTORY_AND_LOCAL_CHALLENGE_REVIEW_ONLY',local_challenge_consumed=True,distributed_challenge_consumption_verified=False)
