"""Structural shift classification; never statutory acceptance."""
import unittest
from app.naruv_kr_payroll_review import shift_night_source_review_2026,PayrollBlocked

class ShiftGuard(unittest.TestCase):
    def call(self,regular=480,overtime=0,holiday_first8=0,holiday_after8=0,night=0):
        total=regular+overtime+holiday_first8+holiday_after8
        end=8*60+total
        return shift_night_source_review_2026(tenant="ci-a",worker="worker-1",period="2026-11",
            segments=[{"start":"2026-11-03T08:00+09:00","end":f"2026-11-03T{end//60:02d}:{end%60:02d}+09:00","evidence_sha256":"a"*64}],
            shift_sha256="b"*64,classified_days=[dict(date="2026-11-03",regular=regular,overtime=overtime,
                holiday_first8=holiday_first8,holiday_after8=holiday_after8,night=night)])
    def test_valid_ordinary(self):
        r=self.call()
        self.assertEqual(r["days"][0]["work_minutes"],480)
        self.assertIs(r["statutory_validated"],False)
        self.assertIs(r["payment_authorized"],False)
    def test_valid_short_holiday(self):
        self.assertEqual(self.call(regular=0,holiday_first8=240)["days"][0]["work_minutes"],240)
    def test_regular_over_eight_hours(self):
        with self.assertRaisesRegex(PayrollBlocked,"KR_SHIFT_CLASSIFIED"):self.call(regular=481)
    def test_holiday_first_over_eight_hours(self):
        with self.assertRaisesRegex(PayrollBlocked,"KR_SHIFT_CLASSIFIED"):self.call(regular=0,holiday_first8=481)
    def test_mixed_ordinary_and_holiday(self):
        with self.assertRaisesRegex(PayrollBlocked,"KR_SHIFT_CLASSIFIED"):self.call(regular=240,holiday_first8=240)
    def test_after_eight_without_first_eight(self):
        with self.assertRaisesRegex(PayrollBlocked,"KR_SHIFT_CLASSIFIED"):self.call(regular=0,holiday_first8=240,holiday_after8=60)

if __name__=="__main__":
    unittest.main()
