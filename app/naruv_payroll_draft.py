"""Deterministic synthetic gross-pay draft; no statutory rules or payment."""
import hashlib
import json
import re
from datetime import date
from fractions import Fraction

ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
PERIOD=re.compile(r"[0-9]{4}-[0-9]{2}")
HEX=re.compile(r"[0-9a-f]{64}")

class PayrollBlocked(ValueError):pass

def require(ok,reason):
    if not ok:raise PayrollBlocked(reason)

def hash_input(x):
    return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def draft_gross(*,tenant,worker,period,policy_revision,hourly_krw,minutes_by_day,multiplier_bps):
    """Only explicitly provided synthetic rates, no implicit overtime threshold.
    Day totals must be supplied by a separate verified attendance source.
    Caller is responsible for authorization; this function has no I/O.
    """
    require(all(type(x) is str and ID.fullmatch(x) for x in (tenant,worker,policy_revision)),"PAY_SCOPE")
    require(type(period) is str and PERIOD.fullmatch(period),"PAY_PERIOD")
    try:date.fromisoformat(period+"-01")
    except ValueError:raise PayrollBlocked("PAY_PERIOD") from None
    require(type(hourly_krw) is int and 1<=hourly_krw<=10**8,"PAY_RATE")
    require(type(multiplier_bps) is dict and set(multiplier_bps)=={"regular","additional"},"PAY_POLICY")
    require(multiplier_bps["regular"]==10000 and all(type(v) is int and 1<=v<=50000 for v in multiplier_bps.values()),"PAY_POLICY")
    require(type(minutes_by_day) in (tuple,list) and 1<=len(minutes_by_day)<=31,"PAY_ROWS")
    normalized=[];seen=set()
    for row in minutes_by_day:
        require(type(row) is dict and set(row)=={"date","regular","additional"},"PAY_ROW")
        day=row["date"];a=row["regular"];b=row["additional"]
        require(type(day) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}",day) and day.startswith(period+"-"),"PAY_DAY")
        try:date.fromisoformat(day)
        except ValueError:raise PayrollBlocked("PAY_DAY") from None
        require(day not in seen,"PAY_DUPLICATE_DAY")
        require(type(a) is int and type(b) is int and 0<=a<=1440 and 0<=b<=1440 and a+b<=1440,"PAY_MINUTES")
        seen.add(day);normalized.append((day,a,b))
    regular=sum(r[1] for r in normalized);additional=sum(r[2] for r in normalized)
    exact=Fraction(hourly_krw*(regular*multiplier_bps["regular"]+additional*multiplier_bps["additional"]),600000)
    # Draft rounding: once at total, half up; statutory policy not assumed.
    gross=(2*exact.numerator+exact.denominator)//(2*exact.denominator)
    require(gross<=10**12,"PAY_LIMIT")
    binding=hash_input({"v":1,"tenant":tenant,"worker":worker,"period":period,"policy":policy_revision,
                        "rate":hourly_krw,"days":sorted(normalized),"multipliers":multiplier_bps})
    return {"draft_sha256":binding,"gross_krw":gross,"regular_minutes":regular,"additional_minutes":additional,
            "status":"SYNTHETIC_GROSS_DRAFT","deductions_krw":None,"net_krw":None,
            "statutory_validated":False,"payment_authorized":False,"requires_human_review":True}
