"""Review-only PostgreSQL failure classification. No automatic retries or I/O.
A transport failure during commit has unknown outcome, not a failed transaction.
Only allowlisted application codes are retained; raw database errors are never emitted.
"""
from dataclasses import dataclass

@dataclass(frozen=True)
class Decision:
    code: str
    action: str
    retry_automatically: bool = False

TRANSIENT = {'40001':'SERIALIZATION_FAILURE','40P01':'DEADLOCK_DETECTED','55P03':'LOCK_NOT_AVAILABLE'}
BLOCK = {'23505':'UNIQUE_VIOLATION','23514':'CHECK_VIOLATION','23503':'FOREIGN_KEY_VIOLATION',
         '23502':'NOT_NULL_VIOLATION','42501':'INSUFFICIENT_PRIVILEGE','25006':'READ_ONLY_TRANSACTION',
         '42P01':'UNDEFINED_TABLE','42883':'UNDEFINED_FUNCTION','53100':'DISK_FULL',
         '58030':'IO_ERROR','57014':'QUERY_CANCELED','25P02':'TRANSACTION_ABORTED'}
APP = {'UNREGISTERED_OR_CONSUMED','BINDING_MISMATCH'}


def classify(sqlstate, *, phase, rollback_confirmed=False, application_code=None):
    if phase not in ('statement','commit','connect','readback'):
        raise ValueError('INVALID_PHASE')
    if type(rollback_confirmed) is not bool:
        raise ValueError('INVALID_ROLLBACK_FLAG')
    if not isinstance(sqlstate,str) or len(sqlstate)!=5 or not sqlstate.isascii() or not sqlstate.isalnum() or sqlstate!=sqlstate.upper():
        sqlstate='UNKNOWN'
    if phase=='commit' and (sqlstate.startswith('08') or sqlstate in ('UNKNOWN','40003','57P01','57P02','57P03','57014','58030')):
        return Decision('COMMIT_OUTCOME_UNKNOWN','READBACK_ON_NEW_CONNECTION')
    if sqlstate=='40003':
        return Decision('STATEMENT_OUTCOME_UNKNOWN','READBACK_ON_NEW_CONNECTION')
    if sqlstate.startswith('08') or sqlstate in ('57P01','57P02','57P03'):
        return Decision('CONNECTION_FAILURE','READBACK_ON_NEW_CONNECTION')
    if sqlstate in TRANSIENT:
        return Decision(TRANSIENT[sqlstate],'READBACK_THEN_RETRY_WHOLE_TRANSACTION' if rollback_confirmed else 'CONFIRM_ROLLBACK_AND_READBACK')
    if sqlstate=='P0001' and type(application_code) is str and application_code in APP:
        return Decision(application_code,'READBACK_NO_REPLAY' if application_code=='UNREGISTERED_OR_CONSUMED' else 'STOP_REVIEW_BINDING')
    if sqlstate in BLOCK:
        action='READBACK_NO_REPLAY' if sqlstate=='23505' else 'STOP_AND_REVIEW'
        if sqlstate=='25P02': action='ROLLBACK_AND_DISCARD_CONNECTION'
        return Decision(BLOCK[sqlstate],action)
    return Decision('UNCLASSIFIED_DATABASE_FAILURE','STOP_AND_READBACK')
