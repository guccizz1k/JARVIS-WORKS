"""Contract: Pengpeng female and Gomi male must be different verified Korean voices."""
import json
import tempfile
import unittest
from pathlib import Path
from scripts.jw_jteam_voice_contract import load_cast, require_distinct_verified_voices

class VoiceContractTests(unittest.TestCase):
    def test_cast_and_korean_script(self):
        c=load_cast()
        self.assertEqual(c["cast"]["pengpeng"]["voice_gender"],"female")
        self.assertEqual(c["cast"]["gomi"]["voice_gender"],"male")
        self.assertEqual(len(c["dialogue"]),6)

    def test_same_voice_rejected(self):
        c=load_cast()
        a={"voice_id":"v1","audio_sha256":"a"*64,"voice_gender":"female","verified_korean_naturalness":True}
        b={"voice_id":"v1","audio_sha256":"b"*64,"voice_gender":"male","verified_korean_naturalness":True}
        with self.assertRaisesRegex(PermissionError,"DUPLICATE_VOICE_ID"):
            require_distinct_verified_voices(c,{"pengpeng":a,"gomi":b})

    def test_same_audio_rejected(self):
        c=load_cast()
        a={"voice_id":"v1","audio_sha256":"a"*64,"voice_gender":"female","verified_korean_naturalness":True}
        b={"voice_id":"v2","audio_sha256":"a"*64,"voice_gender":"male","verified_korean_naturalness":True}
        with self.assertRaisesRegex(PermissionError,"DUPLICATE_AUDIO"):
            require_distinct_verified_voices(c,{"pengpeng":a,"gomi":b})

    def test_wrong_voice_gender_rejected(self):
        c=load_cast()
        a={"voice_id":"v1","audio_sha256":"a"*64,"voice_gender":"male","verified_korean_naturalness":True}
        b={"voice_id":"v2","audio_sha256":"b"*64,"voice_gender":"female","verified_korean_naturalness":True}
        with self.assertRaisesRegex(PermissionError,"WRONG_VOICE_GENDER"):
            require_distinct_verified_voices(c,{"pengpeng":a,"gomi":b})

    def test_language_not_tested_rejected(self):
        c=load_cast()
        a={"voice_id":"v1","audio_sha256":"a"*64,"voice_gender":"female","verified_korean_naturalness":False}
        b={"voice_id":"v2","audio_sha256":"b"*64,"voice_gender":"male","verified_korean_naturalness":True}
        with self.assertRaisesRegex(PermissionError,"KOREAN_VOICE_UNVERIFIED"):
            require_distinct_verified_voices(c,{"pengpeng":a,"gomi":b})

    def test_distinct_verified_audio_passes_gate(self):
        c=load_cast()
        a={"voice_id":"v1","audio_sha256":"a"*64,"voice_gender":"female","verified_korean_naturalness":True}
        b={"voice_id":"v2","audio_sha256":"b"*64,"voice_gender":"male","verified_korean_naturalness":True}
        require_distinct_verified_voices(c,{"pengpeng":a,"gomi":b})

    def test_policy_tampering_blocked(self):
        c=load_cast(); c["single_voice_for_both"]=True
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/"cast.json";p.write_text(json.dumps(c),encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"SHARED_VOICE_FORBIDDEN"):
                load_cast(p)

if __name__=="__main__":unittest.main()
