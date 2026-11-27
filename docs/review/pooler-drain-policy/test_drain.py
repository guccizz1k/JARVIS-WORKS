import unittest
from drain import drain_observed
class DrainTest(unittest.TestCase):
    def run_case(self,counts,budget=180,minimum=125,quiet=15,delay=0):
        t=0; i=0
        def clock():return t
        def nap(n):
            nonlocal t
            assert n>0
            t+=n
        def sample():
            nonlocal i,t
            value=counts[min(i,len(counts)-1)];i+=1;t+=delay
            return value
        return drain_observed(sample,clock,nap,budget,quiet,minimum),t
    def test_zero_waits(self):self.assertEqual(self.run_case([0]),(True,125))
    def test_natural(self):self.assertEqual(self.run_case([3,2,1,0]),(True,125))
    def test_never_zero(self):self.assertEqual(self.run_case([1]),(False,180))
    def test_late_reconnect(self):self.assertEqual(self.run_case([0]*25+[1,0]),(True,145))
    def test_late_zero(self):self.assertEqual(self.run_case([1]*35+[0]),(False,180))
    def test_direct(self):self.assertEqual(self.run_case([0],minimum=0),(True,15))
    def test_boundary(self):self.assertEqual(self.run_case([1]*33+[0]),(True,180))
    def test_slow_query(self):self.assertFalse(self.run_case([0],delay=181)[0])
    def test_invalid(self):
        with self.assertRaises(ValueError):self.run_case([0],budget=100)
    def test_query_failure(self):
        with self.assertRaises(RuntimeError):drain_observed(lambda:(_ for _ in ()).throw(RuntimeError('connection lost')))
if __name__=='__main__':unittest.main(verbosity=2)
