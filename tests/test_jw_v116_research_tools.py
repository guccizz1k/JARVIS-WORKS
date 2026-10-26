"""Local negative tests for V11.6 portable method tools; no external calls."""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from scripts.jw_skill_trial import evaluate
from scripts.jw_visual_parity import compare

SHA='a'*40
def trial(bpass=9,cpass=10,btokens=1000,ctokens=1050):
    def r(ok,tokens,seed):return dict(seed=seed,cases=10,passed=ok,failed=10-ok,skipped=0,tokens=tokens,run_ref=f'test://{seed}/{ok}')
    return dict(schema='jw-paired-skill-trial-v1',code_sha=SHA,suite_sha256='b'*64,
        safety={'baseline':'PASS','candidate':'PASS'},
        baseline=dict(model='model',environment='isolated',skill_sha='c'*40,runs=[r(bpass,btokens,i) for i in range(3)]),
        candidate=dict(model='model',environment='isolated',skill_sha='d'*40,runs=[r(cpass,ctokens,i) for i in range(3)]))

class SkillTrial(unittest.TestCase):
    def test_improvement_never_authorizes_release(self):
        d=evaluate(trial())
        self.assertEqual(d['status'],'CANDIDATE_FOR_INDEPENDENT_VERIFICATION')
        self.assertEqual(d['production_release'],'BLOCKED')
        self.assertFalse(d['independent_result_verified'])
    def test_equal_is_not_improved(self):self.assertEqual(evaluate(trial(9,9))['status'],'NO_MEASURED_GAIN')
    def test_cost_regression(self):self.assertEqual(evaluate(trial(9,10,1000,1600))['status'],'COST_REGRESSION_REVIEW')
    def test_decline(self):self.assertEqual(evaluate(trial(9,8))['status'],'REGRESSION_REVIEW')
    def test_boolean_amount_rejected(self):
        x=trial();x['candidate']['runs'][0]['passed']=True
        self.assertEqual(evaluate(x)['status'],'BLOCKED')
    def test_missing_case_rejected(self):
        x=trial();x['candidate']['runs'][0]['cases']=100
        self.assertEqual(evaluate(x)['status'],'BLOCKED')
    def test_different_seeds_rejected(self):
        x=trial();x['candidate']['runs'][0]['seed']=50
        self.assertEqual(evaluate(x)['reason'],'UNPAIRED_RUNS_OR_ENVIRONMENT')
    def test_duplicate_seed_rejected(self):
        x=trial();x['candidate']['runs'][0]['seed']=1
        self.assertEqual(evaluate(x)['status'],'BLOCKED')
    def test_unpaired_model_rejected(self):
        x=trial();x['candidate']['model']='other'
        self.assertEqual(evaluate(x)['status'],'BLOCKED')
    def test_missing_safety_rejected(self):
        x=trial();x['safety']['candidate']='BLOCKED'
        self.assertEqual(evaluate(x)['reason'],'SAFETY_NOT_PROVEN')
    def test_skip_rejected(self):
        x=trial();x['candidate']['runs'][0].update(passed=8,failed=1,skipped=1)
        self.assertEqual(evaluate(x)['status'],'BLOCKED')
    def test_too_few_replicates(self):
        x=trial();x['baseline']['runs'].pop();self.assertEqual(evaluate(x)['status'],'BLOCKED')
class VisualParity(unittest.TestCase):
    def setUp(self):
        from PIL import Image
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.a=Path(self.temp.name)/'approved.png';self.b=Path(self.temp.name)/'candidate.png'
        Image.new('RGB',(10,10),(255,255,255)).save(self.a)
        Image.new('RGB',(10,10),(255,255,255)).save(self.b)
    def test_unapproved_reference_is_blocked(self):
        self.assertEqual(compare(self.a,self.b,approved_reference=False)['status'],'BLOCKED')
    def test_pixel_equal_but_not_ux_certification(self):
        d=compare(self.a,self.b,approved_reference=True)
        self.assertEqual(d['status'],'PIXEL_MATCH_ONLY');self.assertFalse(d['ux_approved'])
    def test_pixel_mismatch(self):
        from PIL import Image
        im=Image.open(self.b);im.putpixel((2,2),(0,0,0));im.save(self.b)
        d=compare(self.a,self.b,approved_reference=True)
        self.assertEqual(d['changed_pixels'],1)
        self.assertEqual(d['status'],'VISUAL_DIFFERENCE_REVIEW')
    def test_viewport_mismatch(self):
        from PIL import Image
        Image.new('RGB',(9,10),'white').save(self.b)
        self.assertEqual(compare(self.a,self.b,approved_reference=True)['reason'],'VIEWPORT_OR_DPR_MISMATCH')
    def test_invalid_tolerance(self):
        self.assertEqual(compare(self.a,self.b,approved_reference=True,tolerance=True)['reason'],'INVALID_COMPARISON_LIMITS')
    def test_max_pixels_blocks(self):
        self.assertEqual(compare(self.a,self.b,approved_reference=True,max_pixels=1)['reason'],'IMAGE_SIZE_LIMIT')
    def test_disallow_symlink(self):
        p=Path(self.temp.name)/'link.png';p.symlink_to(self.a)
        self.assertEqual(compare(p,self.b,approved_reference=True)['reason'],'INVALID_LOCAL_IMAGE_PATH')
if __name__=='__main__':unittest.main()
