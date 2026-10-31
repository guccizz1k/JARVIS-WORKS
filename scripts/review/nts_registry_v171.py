"""V17.1 isolated Korean NTS business-record verification adapter (OFF).

Only an explicitly approved nonproduction caller can invoke the official
National Tax Service public API with a server-held key. No real lookup occurs
during tests, imports, or staging startup. A business-record match does NOT
prove company-account ownership, delegated signing power or bank settlement.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
import os
import re

import httpx

_VALIDATE = "https://api.odcloud.kr/api/nts-businessman/v1/validate"
_STATUS = "https://api.odcloud.kr/api/nts-businessman/v1/status"
_ACK = "ISOLATED_DEV_NTS_PUBLIC_REGISTRY_ONLY"
_BNO = re.compile(r"^[0-9]{10}$")
_DAY = re.compile(r"^[0-9]{8}$")


class RegistryBlocked(RuntimeError):
    """A fixed, non-sensitive outcome: never format headers or response bodies."""


@dataclass(frozen=True)
class RegistryEvidence:
    business_record_matched: bool
    business_currently_active: bool
    company_account_ownership_verified: bool = False
    representative_authority_verified: bool = False
    bank_reconciliation_verified: bool = False
    independent_issuer_signature_verified: bool = False


def _permit() -> str:
    if (os.getenv("JW_ENV", "").lower() not in ("dev", "development", "test")
            or os.getenv("JW_V171_REGISTRY_ACK") != _ACK
            or os.getenv("JW_INSECURE_LOCAL_DEV") == "1"
            or os.getenv("JW_RELEASE_APPROVED", "").lower() in ("1","yes","true")):
        raise RegistryBlocked("REGISTRY_NOT_AUTHORIZED")
    key = os.getenv("JW_NTS_SERVICE_KEY", "")
    # The key must live on the server. Never log it, echo it or serialize it.
    if not 16 <= len(key) <= 4096 or any(ch.isspace() for ch in key):
        raise RegistryBlocked("REGISTRY_KEY_UNAVAILABLE")
    return key


def _input(b_no: str, start_dt: str, p_nm: str) -> None:
    if type(b_no) is not str or not _BNO.fullmatch(b_no):
        raise RegistryBlocked("INVALID_BUSINESS_NUMBER")
    if type(start_dt) is not str or not _DAY.fullmatch(start_dt):
        raise RegistryBlocked("INVALID_OPEN_DATE")
    try:
        issued = datetime.strptime(start_dt, "%Y%m%d").date()
        if not date(1900, 1, 1) <= issued <= date.today():
            raise ValueError
    except ValueError:
        raise RegistryBlocked("INVALID_OPEN_DATE") from None
    if (type(p_nm) is not str or not 1 <= len(p_nm) <= 60
            or p_nm != p_nm.strip()
            or any(ord(c) < 32 or ord(c) == 127 for c in p_nm)):
        raise RegistryBlocked("INVALID_REPRESENTATIVE")


def _one(response: httpx.Response, number: str, label: str) -> dict:
    # Never follow redirects or parse arbitrarily large untrusted responses.
    try:
        if (response.status_code != 200
                or "json" not in response.headers.get("content-type", "").lower()
                or len(response.content) > 16_384):
            raise ValueError
        body = response.json()
        if (not isinstance(body, dict)
                or body.get("status_code") != "OK"
                or body.get("request_cnt") != 1
                or not isinstance(body.get("data"), list)
                or len(body["data"]) != 1
                or not isinstance(body["data"][0], dict)
                or body["data"][0].get("b_no") != number):
            raise ValueError
        return body["data"][0]
    except (ValueError, TypeError, KeyError):
        raise RegistryBlocked("REGISTRY_" + label + "_UNVERIFIABLE") from None


def check_official_business_record(
    b_no: str, start_dt: str, p_nm: str, *,
    client: httpx.Client | None = None
) -> RegistryEvidence:
    """Check registration record and current status; no DB write or PII storage.

    An injected HTTP client is for deterministic mock tests, not an approval
    bypass: every invocation still requires the explicit environment gate.
    """
    key = _permit()
    _input(b_no, start_dt, p_nm)
    owned_client = client is None
    if owned_client:
        client = httpx.Client(timeout=5, follow_redirects=False, trust_env=False)
    try:
        headers = {"Authorization": key, "Accept": "application/json"}
        validation = client.post(_VALIDATE, json={"businesses":[{
            "b_no": b_no, "start_dt": start_dt, "p_nm": p_nm}]}, headers=headers)
        verdict = _one(validation, b_no, "VALIDATION")
        if verdict.get("valid") != "01":
            return RegistryEvidence(False, False)
        status = client.post(_STATUS, json={"b_no":[b_no]}, headers=headers)
        state = _one(status, b_no, "STATUS")
        active = state.get("b_stt_cd") == "01"
        if state.get("b_stt_cd") not in ("01", "02", "03"):
            raise RegistryBlocked("REGISTRY_UNKNOWN_BUSINESS_STATE")
        return RegistryEvidence(True, active)
    except RegistryBlocked:
        raise
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        raise RegistryBlocked("REGISTRY_TRANSPORT_BLOCKED") from None
    finally:
        if owned_client and client is not None:
            client.close()
