import base64
import unittest
from app.naruv_hr_profile_envelope import seal_profile,open_profile,ProfileBlocked

class HRProfileEnvelope(unittest.TestCase):
    def setUp(self):
        self.scope=dict(tenant="ci-a",worker="pilot-worker",revision="r1",key_id="test-key",key=b"x"*32)
        self.profile=dict(display_name="Synthetic Worker",work_email="worker@example.invalid",employment_start="2026-01-01")
    def test_roundtrip_random_nonce_and_no_plaintext(self):
        a=seal_profile(**self.scope,profile=self.profile)
        b=seal_profile(**self.scope,profile=self.profile)
        self.assertNotEqual(a["nonce"],b["nonce"])
        self.assertNotEqual(a["ciphertext"],b["ciphertext"])
        self.assertEqual(open_profile(**self.scope,envelope=a),self.profile)
        self.assertNotIn(self.profile["work_email"].encode(),base64.b64decode(a["ciphertext"]))
    def test_tenant_worker_revision_key_and_tamper(self):
        a=seal_profile(**self.scope,profile=self.profile)
        for change in ({"tenant":"ci-b"},{"worker":"other"},{"revision":"r2"},{"key_id":"other"},{"key":b"y"*32}):
            with self.subTest(change=change),self.assertRaisesRegex(ProfileBlocked,"HR_PROFILE_INVALID"):
                open_profile(**dict(self.scope,**change),envelope=a)
        c=bytearray(base64.b64decode(a["ciphertext"]));c[-1]^=1
        for bad in (dict(a,ciphertext=base64.b64encode(c).decode()),dict(a,nonce="!"*16),dict(a,v=True),dict(a,extra="unknown")):
            with self.assertRaises(ProfileBlocked):open_profile(**self.scope,envelope=bad)
    def test_minimum_fields_and_strict_validation(self):
        for bad in (dict(self.profile,rrn="synthetic-not-accepted"),
                    dict(self.profile,bank_account="synthetic-not-accepted"),
                    dict(self.profile,display_name="123456"),
                    dict(self.profile,display_name="Name\nInjected"),
                    dict(self.profile,work_email="invalid"),
                    dict(self.profile,employment_start="2026-02-30")):
            with self.assertRaises(ProfileBlocked):seal_profile(**self.scope,profile=bad)
    def test_explicit_key_rotation_reencryption(self):
        a=seal_profile(**self.scope,profile=self.profile)
        new=dict(self.scope,key_id="test-key-2",key=b"z"*32,revision="r2")
        b=seal_profile(**new,profile=open_profile(**self.scope,envelope=a))
        self.assertEqual(open_profile(**new,envelope=b),self.profile)
        with self.assertRaises(ProfileBlocked):open_profile(**self.scope,envelope=b)

    def test_revision_sql_source_integrity(self):
        # Early detection of accidental source duplication; PostgreSQL execution
        # remains the authoritative syntax and behavior acceptance.
        from pathlib import Path
        sql=(Path(__file__).resolve().parents[1]/"db/review/naruv_hr_profile_ci.sql").read_text()
        self.assertEqual(sql.count("CREATE FUNCTION naruv_draft.profile_envelope("),1)
        self.assertEqual(sql.count("RETURN jsonb_build_object('status','SEALED'"),1)
        self.assertEqual(sql.count("RESET ROLE;"),1)
        self.assertEqual(sql.count("CREATE FUNCTION naruv_draft.purge_profile("),1)
        self.assertEqual(sql.count("END $$;"),3)
        self.assertIn("IF p_expected !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_expected=p_revision THEN",sql)
        self.assertTrue(sql.rstrip().endswith("RESET ROLE;"))


    def test_rotation_helper_key_reuse_tamper_and_recovery(self):
        from app.naruv_hr_profile_envelope import rotate_profile
        a=seal_profile(**self.scope,profile=self.profile)
        args=dict(tenant="ci-a",worker="pilot-worker",old_revision="r1",new_revision="r2",
                  old_key_id="test-key",new_key_id="new-key",old_key=b"x"*32,new_key=b"z"*32,envelope=a)
        b=rotate_profile(**args)
        self.assertEqual(open_profile(**dict(self.scope,revision="r2",key_id="new-key",key=b"z"*32),envelope=b),self.profile)
        self.assertEqual(open_profile(**self.scope,envelope=a),self.profile)
        for change in ({"new_key":b"x"*32},{"new_key_id":"test-key"},{"new_revision":"r1"},
                       {"old_key":b"y"*32},{"tenant":"ci-b"},{"envelope":dict(a,nonce="!"*16)}):
            with self.subTest(change=change),self.assertRaises(ProfileBlocked):rotate_profile(**dict(args,**change))

    def test_retention_decision_boundary_and_hold(self):
        from app.naruv_hr_profile_envelope import retention_decision
        from datetime import datetime,timezone,timedelta
        now=datetime(2026,11,26,tzinfo=timezone.utc)
        args=dict(tenant="ci-a",worker="pilot-worker",revision="r1",as_of=now,purpose_closed=True,
                  legal_review_complete=True,legal_hold=False,retain_until=now,approval_sha256="a"*64)
        for change,expected in (({},"PURGE_CANDIDATE_ONLY"),({"purpose_closed":False},"ACTIVE_PURPOSE"),
                ({"legal_review_complete":False},"REVIEW_REQUIRED"),({"approval_sha256":None},"REVIEW_REQUIRED"),
                ({"legal_hold":True},"LEGAL_HOLD_SEPARATE_STORAGE_REQUIRED"),
                ({"legal_hold":True,"legal_review_complete":False},"LEGAL_HOLD_SEPARATE_STORAGE_REQUIRED"),
                ({"retain_until":None},"REVIEW_REQUIRED"),
                ({"retain_until":now+timedelta(microseconds=1)},"RETAIN_SEPARATELY")):
            r=retention_decision(**dict(args,**change))
            self.assertEqual(r["status"],expected)
            self.assertFalse(r["deletion_authorized"]);self.assertFalse(r["production_authorized"])
        for change in ({"as_of":now.replace(tzinfo=None)},{"legal_hold":1},{"approval_sha256":"bad"}):
            with self.assertRaises(ProfileBlocked):retention_decision(**dict(args,**change))


    def test_key_retirement_review_coverage_and_scope(self):
        from app.naruv_hr_profile_envelope import key_retirement_review,retirement_inventory_digest
        row=dict(asset="live",tenant="ci-a",key_id="new",restore_sha256="a"*64,old_key_denied=True)
        archive=dict(row,asset="archive")
        scope=dict(tenant="ci-a",old_key_id="old",new_key_id="new",expected_assets=["live","archive"])
        args=dict(scope,inventory_sha256=retirement_inventory_digest(**scope),observations=[row,archive])
        r=key_retirement_review(**args)
        self.assertEqual(r["status"],"EVIDENCE_REVIEW_ONLY")
        self.assertIs(r["key_retirement_authorized"],False)
        self.assertEqual(r,key_retirement_review(**dict(args,observations=[archive,row])))
        for obs,missing,blocked in (([row],["archive"],[]),
          ([row,dict(archive,key_id="old")],[],["archive"]),
          ([row,dict(archive,old_key_denied=False)],[],["archive"])):
            out=key_retirement_review(**dict(args,observations=obs))
            self.assertEqual((out["status"],out["missing_assets"],out["blocked_assets"]),("BLOCKED",missing,blocked))
        for change in (dict(observations=[row,row]),dict(observations=[row,dict(archive,tenant="ci-b")]),
          dict(observations=[row,dict(archive,restore_sha256="bad")]),dict(expected_assets=[]),
          dict(expected_assets=["live","live"]),dict(new_key_id="old")):
            with self.assertRaises(ProfileBlocked):key_retirement_review(**dict(args,**change))
        for change in (dict(inventory_sha256="c"*64),dict(expected_assets=["live"],observations=[row]),
                       dict(tenant="ci-b"),dict(new_key_id="another")):
            with self.assertRaises(ProfileBlocked):key_retirement_review(**dict(args,**change))
        self.assertEqual(r,key_retirement_review(**dict(args,expected_assets=["archive","live"])))
        changed=key_retirement_review(**dict(args,observations=[row,dict(archive,restore_sha256="c"*64)]))
        self.assertNotEqual(r["review_sha256"],changed["review_sha256"])

    def test_independent_retirement_attestations(self):
        from datetime import datetime,timezone,timedelta
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        from app.naruv_hr_profile_envelope import key_retirement_review,retirement_inventory_digest,verify_retirement_attestations,_canonical
        scope=dict(tenant="ci-a",old_key_id="old",new_key_id="new",expected_assets=["live"])
        digest=retirement_inventory_digest(**scope)
        review=key_retirement_review(**scope,inventory_sha256=digest,observations=[dict(asset="live",tenant="ci-a",key_id="new",restore_sha256="a"*64,old_key_denied=True)])
        now=datetime(2026,11,26,tzinfo=timezone.utc); challenge="c"*64
        a,b=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
        msg=_canonical(["NARUV_RETIREMENT_ATTESTATION_V1",digest,review["review_sha256"],challenge,now.isoformat()])
        args=dict(review=review,inventory_sha256=digest,challenge=challenge,issued_at=now,as_of=now,
            inventory_public_key=a.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
            recovery_public_key=b.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
            inventory_signature=a.sign(b"inventory:"+msg),recovery_signature=b.sign(b"recovery:"+msg))
        self.assertEqual(verify_retirement_attestations(**args)["status"],"SIGNED_EVIDENCE_REVIEW_ONLY")
        self.assertFalse(verify_retirement_attestations(**args)["key_retirement_authorized"])
        for change in (dict(challenge="d"*64),dict(inventory_sha256="e"*64),dict(as_of=now+timedelta(minutes=10,microseconds=1)),
                       dict(as_of=now-timedelta(seconds=1)),dict(recovery_signature=args["inventory_signature"]),
                       dict(recovery_public_key=args["inventory_public_key"]),dict(review=dict(review,status="BLOCKED")),
                       dict(review=dict(review,review_sha256="f"*64))):
            with self.subTest(change=list(change)),self.assertRaises(ProfileBlocked):verify_retirement_attestations(**dict(args,**change))


    def test_archive_lifecycle_holds_and_old_key_dependencies(self):
        import hashlib
        from datetime import datetime,timezone,timedelta
        from app.naruv_hr_profile_envelope import archive_lifecycle_review,_canonical
        now=datetime(2026,11,26,tzinfo=timezone.utc)
        row=dict(asset="old-copy",tenant="ci-a",archive_sha256="a"*64,
                 retain_until=now+timedelta(days=1),legal_hold=True,old_key_required=True)
        other=dict(row,asset="new-copy",archive_sha256="b"*64,retain_until=now,legal_hold=False,old_key_required=False)
        expected=["old-copy","new-copy"]
        def digest(records):
            values=[[x["asset"],x["archive_sha256"],None if x["retain_until"] is None else x["retain_until"].isoformat(),
                     x["legal_hold"],x["old_key_required"]] for x in records]
            return hashlib.sha256(_canonical(["NARUV_ARCHIVE_LIFECYCLE_V1","ci-a",sorted(expected),sorted(values)])).hexdigest()
        args=dict(tenant="ci-a",as_of=now,expected_assets=expected,records=[row,other],inventory_sha256=digest([row,other]))
        r=archive_lifecycle_review(**args)
        self.assertEqual(r["status"],"BLOCKED")
        self.assertEqual(r["old_key_assets"],["old-copy"])
        self.assertEqual(r["legal_hold_assets"],["old-copy"])
        self.assertEqual(r["retained_assets"],["old-copy"])
        self.assertFalse(r["deletion_authorized"])
        self.assertEqual(r,archive_lifecycle_review(**dict(args,records=[other,row])))
        with self.assertRaises(ProfileBlocked):archive_lifecycle_review(**dict(args,records=[other]))
        incomplete=archive_lifecycle_review(**dict(args,records=[other],inventory_sha256=digest([other])))
        self.assertEqual(incomplete["missing_assets"],["old-copy"])
        unknown=dict(row,retain_until=None,legal_hold=False,old_key_required=False)
        r=archive_lifecycle_review(**dict(args,records=[unknown,other],inventory_sha256=digest([unknown,other])))
        self.assertEqual(r["unknown_retention_assets"],["old-copy"])
        clear=dict(row,retain_until=now,legal_hold=False,old_key_required=False)
        r=archive_lifecycle_review(**dict(args,records=[clear,other],inventory_sha256=digest([clear,other])))
        self.assertEqual(r["status"],"EVIDENCE_REVIEW_ONLY")
        self.assertFalse(r["key_retirement_authorized"])
        self.assertFalse(r["production_authorized"])


    def test_combined_evidence_uses_pinned_signers_and_recomputed_reviews(self):
        from datetime import datetime,timezone,timedelta
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        from app.naruv_hr_profile_envelope import (_canonical,retirement_inventory_digest,key_retirement_review,
            archive_lifecycle_review,verify_combined_retirement_evidence)
        now=datetime(2026,11,26,tzinfo=timezone.utc)
        scope=dict(tenant="ci-a",old_key_id="old",new_key_id="new",expected_assets=["live","archive"])
        inventory=retirement_inventory_digest(**scope)
        observations=[dict(asset=x,tenant="ci-a",key_id="new",restore_sha256="a"*64,old_key_denied=True) for x in scope["expected_assets"]]
        review=key_retirement_review(**scope,inventory_sha256=inventory,observations=observations)
        rows=[dict(asset="archive",tenant="ci-a",archive_sha256="b"*64,retain_until=now,legal_hold=False,old_key_required=False)]
        archive=hashlib.sha256(_canonical(["NARUV_ARCHIVE_LIFECYCLE_V1","ci-a",["archive"],[["archive","b"*64,now.isoformat(),False,False]]])).hexdigest()
        life=archive_lifecycle_review(tenant="ci-a",as_of=now,expected_assets=["archive"],inventory_sha256=archive,records=rows)
        a,b=Ed25519PrivateKey.generate(),Ed25519PrivateKey.generate()
        ap,bp=(k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw) for k in (a,b))
        trust={"inventory":hashlib.sha256(ap).hexdigest(),"recovery":hashlib.sha256(bp).hexdigest()}
        challenge="c"*64
        msg=_canonical(["NARUV_COMBINED_RETIREMENT_V2","ci-a","old","new",inventory,
            review["review_sha256"],archive,life["review_sha256"],trust,challenge,now.isoformat()])
        args=dict(scope,inventory_sha256=inventory,observations=observations,expected_archive_assets=["archive"],
            archive_inventory_sha256=archive,archive_records=rows,inventory_public_key=ap,recovery_public_key=bp,
            trust_fingerprints=trust,inventory_signature=a.sign(b"inventory:"+msg),recovery_signature=b.sign(b"recovery:"+msg),
            challenge=challenge,issued_at=now,as_of=now)
        r=verify_combined_retirement_evidence(**args)
        self.assertTrue(r["requires_atomic_challenge_consumption"])
        self.assertFalse(r["key_retirement_authorized"])
        for change in (dict(observations=observations[:1]),dict(archive_records=[]),
            dict(archive_records=[dict(rows[0],legal_hold=True)]),
            dict(expected_archive_assets=["unknown"]),dict(trust_fingerprints=dict(trust,inventory="d"*64)),
            dict(challenge="e"*64),dict(as_of=now+timedelta(minutes=11)),
            dict(recovery_signature=args["inventory_signature"])):
            with self.subTest(change=list(change)),self.assertRaises(ProfileBlocked):
                verify_combined_retirement_evidence(**dict(args,**change))


    def test_mounted_key_store_read_only_rotation_and_denial(self):
        import os,tempfile
        from pathlib import Path
        from app.naruv_hr_profile_envelope import MountedProfileKeyStore
        if not hasattr(os,"O_NOFOLLOW"):self.skipTest("POSIX key mount required")
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,material in (("old",b"x"*32),("new",b"y"*32),("other",b"z"*32)):
                p=root/(name+".key");p.write_bytes(material);p.chmod(0o600)
            manifest={"ci-a":{"test-key":{"file":"old.key","state":"RECOVERY_ONLY"},
                "new-key":{"file":"new.key","state":"ACTIVE"}},
                "ci-b":{"other":{"file":"other.key","state":"ACTIVE"}}}
            store=MountedProfileKeyStore(tmp,manifest)
            old=seal_profile(**self.scope,profile=self.profile)
            rotated=store.rotate(tenant="ci-a",worker="pilot-worker",old_revision="r1",new_revision="r2",envelope=old)
            self.assertEqual(rotated["key_id"],"new-key")
            self.assertEqual(store.recover(tenant="ci-a",worker="pilot-worker",revision="r2",envelope=rotated),self.profile)
            self.assertEqual(store.recover(tenant="ci-a",worker="pilot-worker",revision="r1",envelope=old),self.profile)
            self.assertEqual(store.seal(tenant="ci-a",worker="pilot-worker",revision="r3",profile=self.profile)["key_id"],"new-key")
            with self.assertRaises(ProfileBlocked):store.recover(tenant="ci-b",worker="pilot-worker",revision="r2",envelope=rotated)
            for mode in (0o644,0o660):
                (root/"new.key").chmod(mode)
                with self.assertRaises(ProfileBlocked):store.recover(tenant="ci-a",worker="pilot-worker",revision="r2",envelope=rotated)
            (root/"new.key").chmod(0o600)
            os.link(root/"new.key",root/"hardlink.key")
            with self.assertRaises(ProfileBlocked):store.seal(tenant="ci-a",worker="pilot-worker",revision="r3",profile=self.profile)
            (root/"hardlink.key").unlink()
            (root/"new.key").rename(root/"saved.key")
            (root/"new.key").symlink_to(root/"saved.key")
            with self.assertRaises(ProfileBlocked):store.seal(tenant="ci-a",worker="pilot-worker",revision="r3",profile=self.profile)
            self.assertEqual((root/"old.key").read_bytes(),b"x"*32)
            self.assertEqual((root/"saved.key").read_bytes(),b"y"*32)


    def test_incident_quarantine_and_pinned_material(self):
        import tempfile,hashlib
        from pathlib import Path
        from app.naruv_hr_profile_envelope import IncidentPinnedKeyStore
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"active.key";path.write_bytes(b"x"*32);path.chmod(0o600)
            manifest={"ci-a":{"test-key":{"file":"active.key","state":"ACTIVE"}}}
            pins={"ci-a":{"test-key":hashlib.sha256(b"x"*32).hexdigest()}}
            store=IncidentPinnedKeyStore(tmp,manifest,pins,[])
            old=store.seal(tenant="ci-a",worker="pilot-worker",revision="r1",profile=self.profile)
            self.assertEqual(store.recover(tenant="ci-a",worker="pilot-worker",revision="r1",envelope=old),self.profile)
            blocked=IncidentPinnedKeyStore(tmp,manifest,pins,[("ci-a","test-key")])
            with self.assertRaises(ProfileBlocked):blocked.recover(tenant="ci-a",worker="pilot-worker",revision="r1",envelope=old)
            with self.assertRaises(ProfileBlocked):blocked.seal(tenant="ci-a",worker="pilot-worker",revision="r1",profile=self.profile)
            path.write_bytes(b"y"*32)
            with self.assertRaises(ProfileBlocked):store.seal(tenant="ci-a",worker="pilot-worker",revision="r1",profile=self.profile)

    def test_provider_inventory_missing_retention_and_mismatch(self):
        import hashlib
        from app.naruv_hr_profile_envelope import _canonical,reconcile_backup_provider_inventory
        a=dict(asset="archive",tenant="ci-a",provider="GITHUB_PRIVATE",sha256="a"*64,key_id="old",
            retention_verified=False,restore_verified=True)
        b=dict(a,provider="BACKBLAZE_B2",retention_verified=True)
        def call(rows):
            digest=hashlib.sha256(_canonical(["NARUV_PROVIDER_INVENTORY_V1","ci-a",["archive"],sorted(rows,key=lambda r:(r["asset"],r["provider"]))])).hexdigest()
            return reconcile_backup_provider_inventory(tenant="ci-a",expected_assets=["archive"],records=rows,inventory_sha256=digest)
        self.assertEqual(call([a,b])["status"],"INVENTORY_MATCH_ONLY")
        self.assertEqual(call([a])["missing_assets"],["archive"])
        self.assertEqual(call([a,dict(b,retention_verified=False)])["mismatch_assets"],["archive"])
        self.assertEqual(call([a,dict(b,sha256="b"*64)])["status"],"BLOCKED")
        self.assertFalse(call([a,b])["key_retirement_authorized"])

    def test_provider_inventory_independent_original_manifest(self):
        import hashlib
        from app.naruv_hr_profile_envelope import _canonical,reconcile_backup_provider_inventory_against_manifest
        a=dict(asset="archive",tenant="ci-a",provider="GITHUB_PRIVATE",sha256="a"*64,key_id="old",
            retention_verified=False,restore_verified=True)
        b=dict(a,provider="BACKBLAZE_B2",retention_verified=True)
        original={"archive":{"sha256":"a"*64,"key_id":"old"}}
        pin=hashlib.sha256(_canonical(["NARUV_ORIGINAL_BACKUP_MANIFEST_V1","ci-a",original])).hexdigest()
        def call(rows,**kw):
            digest=hashlib.sha256(_canonical(["NARUV_PROVIDER_INVENTORY_V1","ci-a",["archive"],
                sorted(rows,key=lambda r:(r["asset"],r["provider"]))])).hexdigest()
            args=dict(tenant="ci-a",expected_manifest=original,expected_manifest_sha256=pin,records=rows,inventory_sha256=digest)
            return reconcile_backup_provider_inventory_against_manifest(**dict(args,**kw))
        good=call([a,b])
        self.assertEqual(good["status"],"ORIGINAL_AND_PROVIDER_MATCH_ONLY")
        self.assertFalse(good["key_retirement_authorized"])
        self.assertFalse(good["production_authorized"])
        for change in (dict(sha256="b"*64),dict(key_id="new")):
            r=call([dict(a,**change),dict(b,**change)])
            self.assertEqual(r["status"],"BLOCKED")
            self.assertEqual(r["original_mismatch_assets"],["archive"])
        self.assertEqual(call([a])["status"],"BLOCKED")
        self.assertEqual(call([a,dict(b,retention_verified=False)])["status"],"BLOCKED")
        for change in (dict(expected_manifest_sha256="0"*64),
            dict(expected_manifest={"archive":{"sha256":"c"*64,"key_id":"old"}})):
            with self.assertRaises(ProfileBlocked):call([a,b],**change)


    def test_b2_compliance_metadata_fail_closed(self):
        from app.naruv_hr_profile_envelope import review_b2_compliance_version_metadata as review
        upload=1800000000000
        e={"fileId":"v1","contentLength":123,"contentSha1":"a"*40}
        row=dict(e,bucketId="b",fileName="synthetic/a",action="upload",uploadTimestamp=upload,
            fileRetention={"isClientAuthorizedToRead":True,"value":{"mode":"compliance","retainUntilTimestamp":upload+30*86400000}},
            legalHold={"isClientAuthorizedToRead":True,"value":"off"},
            serverSideEncryption={"mode":"SSE-B2","algorithm":"AES256"})
        def page(rows,n=None,f=None,s=None,i=None):
            return {"startFileName":s,"startFileId":i,"response":{"files":rows,"nextFileName":n,"nextFileId":f}}
        def call(pages,now=upload+1):
            return review(bucket_id="b",expected={"synthetic/a":e},pages=pages,as_of_ms=now)
        good=call([page([row])])
        self.assertEqual(good["status"],"B2_COMPLIANCE_METADATA_MATCH_ONLY")
        self.assertFalse(good["sha256_verified"])
        self.assertFalse(good["restore_verified"])
        self.assertFalse(good["deletion_authorized"])
        for bad in (dict(row,action="hide"),dict(row,fileId="v2"),dict(row,contentSha1="b"*40),
                dict(row,fileRetention={"isClientAuthorizedToRead":False,"value":None}),
                dict(row,fileRetention={"isClientAuthorizedToRead":True,"value":{"mode":"governance","retainUntilTimestamp":upload+30*86400000}}),
                dict(row,fileRetention={"isClientAuthorizedToRead":True,"value":{"mode":"compliance","retainUntilTimestamp":upload+29*86400000}}),
                dict(row,legalHold={"isClientAuthorizedToRead":False,"value":None}),
                dict(row,serverSideEncryption=None),dict(row,serverSideEncryption={"mode":"SSE-C","algorithm":"AES256"}),
                dict(row,serverSideEncryption={"mode":"SSE-B2","algorithm":None})):
            with self.subTest(bad=bad):self.assertEqual(call([page([bad])])["status"],"BLOCKED")
        self.assertEqual(call([page([])])["status"],"BLOCKED")
        self.assertEqual(call([page([row])],upload+30*86400000)["status"],"BLOCKED")
        self.assertEqual(call([page([row,dict(row,fileId="v2")])])["status"],"BLOCKED")
        with self.assertRaises(ProfileBlocked):call([page([row],"next","v2")])
        with self.assertRaises(ProfileBlocked):call([page([row],"next","v2"),page([dict(row,fileId="v2")],s="wrong",i="v2")])


    def test_key_directory_ancestor_symlink_and_writable_denial(self):
        import os,tempfile
        from pathlib import Path
        from app.naruv_hr_profile_envelope import MountedProfileKeyStore
        if not hasattr(os,"O_NOFOLLOW"):self.skipTest("POSIX required")
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);parent=root/"parent";parent.mkdir(mode=0o700)
            leaf=parent/"keys";leaf.mkdir(mode=0o700)
            key=leaf/"active.key";key.write_bytes(b"x"*32);key.chmod(0o600)
            manifest={"ci-a":{"test-key":{"file":"active.key","state":"ACTIVE"}}}
            def seal(p):
                return MountedProfileKeyStore(str(p),manifest).seal(tenant="ci-a",
                    worker="pilot-worker",revision="r1",profile=self.profile)
            self.assertEqual(seal(leaf)["key_id"],"test-key")
            alias=root/"alias";alias.symlink_to(parent,target_is_directory=True)
            with self.assertRaises(ProfileBlocked):seal(alias/"keys")
            with self.assertRaises(ProfileBlocked):seal(str(parent)+"/../parent/keys")
            with self.assertRaises(ProfileBlocked):seal(str(parent)+"//keys")
            parent.chmod(0o777)
            with self.assertRaises(ProfileBlocked):seal(leaf)
            parent.chmod(0o700)
            self.assertEqual(seal(leaf)["key_id"],"test-key")
