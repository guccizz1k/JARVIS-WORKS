import copy,pytest
from scripts import naruv_owner_b2_metadata_review as m

def test_exact_version_rejects_drift():
    r={"fileName":"n","fileId":"id","contentLength":40,"accountId":"a"}
    assert m.exact_row({"files":[r]},"n","id",40,"a")==r
    for k,v in (("fileId","other"),("contentLength",41),("fileName","other"),("accountId","b")):
        b=dict(r,**{k:v})
        with pytest.raises(ValueError):m.exact_row({"files":[b]},"n","id",40,"a")
    for rows in ([],[r,r]):
        with pytest.raises(ValueError):m.exact_row({"files":rows},"n","id",40,"a")

def test_temp_scope(monkeypatch):
    monkeypatch.setattr(m,"BUCKET",m.sha(b"bucket"))
    monkeypatch.setattr(m,"now",lambda:100)
    d={"accountId":"a","applicationKeyExpirationTimestamp":200,"apiInfo":{"storageApi":{"allowed":{"buckets":[{"id":"b","name":"bucket"}],"capabilities":sorted(m.CAPS),"namePrefix":m.PREFIX}}}}
    m.scope(d,"a","b",200)
    for extra in ("readFiles","shareFiles","writeFiles","deleteFiles"):
        x=copy.deepcopy(d);x["apiInfo"]["storageApi"]["allowed"]["capabilities"].append(extra)
        with pytest.raises(ValueError):m.scope(x,"a","b",200)
    for expiry in (100,201):
        with pytest.raises(ValueError):m.scope(d,"a","b",expiry)

def test_api_denies_download_and_mutation(monkeypatch):
    monkeypatch.setattr(m,"request",lambda *a:pytest.fail("unexpected network"))
    for op in ("b2_download_file_by_id","b2_update_file_retention","b2_delete_file_version","b2_get_file_info"):
        with pytest.raises(ValueError,match="METHOD_DENIED"):m.api({},op,{})

def test_bucket_configuration():
    row={"bucketId":"b","bucketName":"n","accountId":"a","bucketType":"allPrivate","fileLockConfiguration":{"isClientAuthorizedToRead":True,"value":{"isFileLockEnabled":True}},"defaultServerSideEncryption":{"isClientAuthorizedToRead":True,"value":{"mode":"SSE-B2","algorithm":"AES256"}}}
    m.bucket_check({"buckets":[row]},"b","n","a")
    for k,v in (("bucketType","allPublic"),("fileLockConfiguration",{"isClientAuthorizedToRead":False}),("defaultServerSideEncryption",{"isClientAuthorizedToRead":True,"value":{"mode":"none"}})):
        with pytest.raises(ValueError):m.bucket_check({"buckets":[dict(row,**{k:v})]},"b","n","a")
