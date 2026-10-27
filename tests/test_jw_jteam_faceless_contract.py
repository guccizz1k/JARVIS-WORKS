import unittest
from scripts.jw_jteam_universal_work_order import read_contract, plan

class NoFilmingCreatorContract(unittest.TestCase):
    def test_user_does_not_prepare_assets(self):
        policy=read_contract()["faceless_content_policy"]
        for name in ("user_filming_required","user_voice_recording_required",
                     "user_script_writing_required","user_editing_required",
                     "user_media_assets_required"):
            self.assertIs(policy[name],False)
    def test_no_unsupported_completion_claim(self):
        result=plan("유튜브 쇼츠 자동 콘텐츠 제작")
        self.assertIs(result["media_rendered"],False)
        self.assertIs(result["publication_performed"],False)
        self.assertIs(result["user_filming_required"],False)
        self.assertEqual(result["paid_calls"],0)

if __name__=="__main__":
    unittest.main()
