"""Standalone review screen, not the approved NARUV UI. No write action.
Only validated adjustment proposals. No customer or worker identifier shown.
"""
from html import escape
from review_gates import need,digest
from postconfirm_adjustment import sha

def render(record):
    need(type(record) is dict and record.get('status')=='POSTCONFIRM_ADJUSTMENT_PROPOSAL_ONLY' and all(record.get(k) is False for k in ('payment_authorized','recovery_authorized','statutory_validated','production_authorized')),'VIEW_SCOPE')
    core={k:v for k,v in record.items() if k not in ('proposal_sha256','status','payment_authorized','recovery_authorized','statutory_validated','production_authorized')}
    need(digest(record.get('proposal_sha256')) and sha(core)==record['proposal_sha256'],'VIEW_PIN')
    c=record['comparison'];vals=[c.get(k) for k in ('gross_delta_krw','deductions_delta_krw','net_delta_krw')]
    need(all(type(v) is int and abs(v)<=10**12 for v in vals) and vals[0]-vals[1]==vals[2],'VIEW_AMOUNTS')
    warning='음수 차액 — 환수 금지, 별도 검토 필요' if vals[2]<0 else '지급 승인 없이 검토만 가능'
    rows=''.join('<tr><th scope="row">'+label+'</th><td>'+format(v,',')+' 원</td></tr>' for label,v in zip(('지급총액 차액','공제액 차액','실수령액 차액'),vals))
    return '''<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'"><title>급여 정정 검토</title><style>body{background:#111;color:#eee;font:18px system-ui,sans-serif;margin:0}main{max-width:780px;margin:48px auto;padding:24px}h1{color:#c9f75b}table{width:100%;border-collapse:collapse}th,td{padding:16px;text-align:left;border-bottom:1px solid #555}td{text-align:right;font-variant-numeric:tabular-nums}.notice{border:1px solid #999;padding:16px}.mobile{display:none}@media(max-width:767px){main{display:none}.mobile{display:block;padding:24px}}</style></head><body><main><h1>급여 정정 검토</h1><p class="notice" role="status">'''+escape(warning)+'''</p><table aria-label="정정 차액"><tbody>'''+rows+'''</tbody></table><p>확정 원본은 변경되지 않습니다. 법정 적합성 및 지급·환수 권한 미검증.</p></main><p class="mobile">PC에서 검토 화면을 이용하십시오.</p></body></html>'''
