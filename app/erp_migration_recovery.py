"""Fail-closed outcome reconciliation for the isolated PG17 fixture lab.

Receipt readback is not authorization to write or retry. This module has no
database connection, I/O, clocks, or ability to issue a new import.
"""

def classify(approval, receipt, reservation_id):
    if type(reservation_id) is not str or not reservation_id:
        return "BLOCKED_INVALID_EVIDENCE"
    if approval is None:
        return "UNKNOWN" if receipt is None else "BLOCKED_INCONSISTENT"
    if (type(approval) is not tuple or len(approval)!=3
            or type(approval[0]) is not str or approval[2] is not False
            or (approval[1] is not None and type(approval[1]) is not str)):
        return "BLOCKED_INVALID_EVIDENCE"
    status, reserved_id, _ = approval
    if receipt is not None:
        if (type(receipt) is not tuple or len(receipt)!=3
                or receipt[0]!="FIXTURE_COMMITTED"
                or type(receipt[1]) is not int or not 1<=receipt[1]<=1000
                or receipt[2] is not False):
            return "BLOCKED_INVALID_EVIDENCE"
        if status=="RESERVED" and reserved_id==reservation_id:
            return "COMMITTED_RECEIPT_PRESENT"
        return "BLOCKED_INCONSISTENT"
    if status=="APPROVED" and reserved_id is None:
        return "NOT_COMMITTED_AT_CHECK"
    if status=="REVOKED" and reserved_id is None:
        return "BLOCKED_REVOKED"
    # A reservation is NOT proof of a completed transaction.
    return "BLOCKED_INCONSISTENT"


def result(approval, receipt, reservation_id):
    return {"outcome":classify(approval,receipt,reservation_id),
            "automatic_retry":False,"production_import_authorized":False}
