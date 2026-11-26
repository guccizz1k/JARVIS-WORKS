import base64
import pytest
from scripts import naruv_offline_key_copy_check as m

A=base64.urlsafe_b64encode(b'a'*32).decode()
B=base64.urlsafe_b64encode(b'b'*32).decode()


def test_valid():
    result=m.compare((A,A,A),(B,B,B))
    assert result['copy_values_match'] and result['copies_compared']==4
    assert not result['storage_independence_verified'] and not result['archive_authentication_verified']
    assert result['p2_acceptance']=='BLOCKED' and A not in str(result) and B not in str(result)


@pytest.mark.parametrize('a,b', [((A,A,B),(B,B,B)),((A,B,A),(B,B,B)),((A,A,A),(B,A,B)),((A,A,A),(B,B,A)),((A,A,A),(A,A,A)),((A,A),(B,B,B)),((A,A,A.rstrip('=')),(B,B,B)),((A,A,'!'),(B,B,B))])
def test_invalid(a,b):
    with pytest.raises(ValueError):m.compare(a,b)
