import pytest
from unittest.mock import patch
from scripts import ci_cinema_pg_v6_login_diagnostic as d

@pytest.mark.parametrize('message,expected',[
 ('SOURCE_AUTH_ONLY_PASS: no backup','PASS'),
 ('BLOCKED: source role does not meet the expected identity/privileges: foo','SOURCE_IDENTITY_OR_PRIVILEGES'),
 ('BLOCKED: live read-only login or guard failed [OperationalError]','SOURCE_LOGIN_OPERATIONALERROR'),
 ('BLOCKED: live read-only login or guard failed [ValueError]','SOURCE_LOGIN_VALUEERROR'),
 ('BLOCKED: live read-only login or guard failed [secret]','SOURCE_LOGIN_OTHER_ERROR'),
 ('BLOCKED: use the approved Codespace only','CODESPACE_GUARD'),
 ('password=private','SOURCE_LOGIN_UNCLASSIFIED')
])
def test_categories_never_echo_secret(message,expected):
    assert d.classify(message)==expected

def test_failure_is_sanitized():
    with patch('scripts.ci_cinema_pg_u.main',return_value=2):
        with pytest.raises(d.LoginBlocked,match='SOURCE_LOGIN_UNCLASSIFIED'):
            d.stage_login()
