import pytest
from scripts.naruv_pg_error_policy_review import classify

@pytest.mark.parametrize('state,phase,rollback,code,action',[
 ('40001','statement',True,'SERIALIZATION_FAILURE','READBACK_THEN_RETRY_WHOLE_TRANSACTION'),
 ('40P01','statement',True,'DEADLOCK_DETECTED','READBACK_THEN_RETRY_WHOLE_TRANSACTION'),
 ('55P03','statement',False,'LOCK_NOT_AVAILABLE','CONFIRM_ROLLBACK_AND_READBACK'),
 ('23505','statement',True,'UNIQUE_VIOLATION','READBACK_NO_REPLAY'),
 ('23514','statement',True,'CHECK_VIOLATION','STOP_AND_REVIEW'),
 ('23503','statement',True,'FOREIGN_KEY_VIOLATION','STOP_AND_REVIEW'),
 ('23502','statement',True,'NOT_NULL_VIOLATION','STOP_AND_REVIEW'),
 ('42501','statement',False,'INSUFFICIENT_PRIVILEGE','STOP_AND_REVIEW'),
 ('25006','statement',False,'READ_ONLY_TRANSACTION','STOP_AND_REVIEW'),
 ('42P01','statement',False,'UNDEFINED_TABLE','STOP_AND_REVIEW'),
 ('42883','statement',False,'UNDEFINED_FUNCTION','STOP_AND_REVIEW'),
 ('53100','statement',False,'DISK_FULL','STOP_AND_REVIEW'),
 ('58030','statement',False,'IO_ERROR','STOP_AND_REVIEW'),
 ('25P02','statement',False,'TRANSACTION_ABORTED','ROLLBACK_AND_DISCARD_CONNECTION'),
 ('57014','statement',False,'QUERY_CANCELED','STOP_AND_REVIEW'),
 ('08006','commit',False,'COMMIT_OUTCOME_UNKNOWN','READBACK_ON_NEW_CONNECTION'),
 ('40003','commit',False,'COMMIT_OUTCOME_UNKNOWN','READBACK_ON_NEW_CONNECTION'),
 (None,'commit',False,'COMMIT_OUTCOME_UNKNOWN','READBACK_ON_NEW_CONNECTION'),
 ('57P01','commit',False,'COMMIT_OUTCOME_UNKNOWN','READBACK_ON_NEW_CONNECTION'),
 ('57014','commit',False,'COMMIT_OUTCOME_UNKNOWN','READBACK_ON_NEW_CONNECTION'),
 ('08001','connect',False,'CONNECTION_FAILURE','READBACK_ON_NEW_CONNECTION'),
 ('40003','statement',False,'STATEMENT_OUTCOME_UNKNOWN','READBACK_ON_NEW_CONNECTION'),
 ('secret','statement',False,'UNCLASSIFIED_DATABASE_FAILURE','STOP_AND_READBACK'),
])
def test_policy(state,phase,rollback,code,action):
    d=classify(state,phase=phase,rollback_confirmed=rollback)
    assert (d.code,d.action,d.retry_automatically)==(code,action,False)

@pytest.mark.parametrize('app,expected',[('UNREGISTERED_OR_CONSUMED','UNREGISTERED_OR_CONSUMED'),('BINDING_MISMATCH','BINDING_MISMATCH'),('sensitive internal value','UNCLASSIFIED_DATABASE_FAILURE'),([], 'UNCLASSIFIED_DATABASE_FAILURE')])
def test_application_code(app,expected):
    d=classify('P0001',phase='statement',application_code=app)
    assert d.code==expected and not d.retry_automatically

def test_invalid_context():
    with pytest.raises(ValueError,match='INVALID_PHASE'):classify('40001',phase='oops')
    with pytest.raises(ValueError,match='INVALID_ROLLBACK_FLAG'):classify('40001',phase='statement',rollback_confirmed=1)
