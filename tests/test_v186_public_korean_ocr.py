"""V18.6 exact numeric-token boundaries and fail-closed size handling."""
import pytest
from scripts.ci_v186_public_korean_ocr import numeric_candidates, SAMPLES, ACK

CASES=(
 ("사업자번호 301-85-41046",{"3018541046"}),
 ("사업자번호 3018541046",{"3018541046"}),
 ("합계 3,980원",{"3980"}),
 ("합계 3 980원",set()),
 ("합계 3.980원",set()),
 ("합계 3560원",{"3560"}),
 ("2025-12-26",set()),
 ("12:30",set()),
 ("카드번호: 1234****5678",{"1234","5678"}),
 ("매장 358원",set()),
 ("총합 0001",{"0001"}),
 ("금액 9,999,999",{"9999999"}),
 ("abc123456",{"123456"}),
 ("abc123456x",{"123456"}),
 ("9999999999999",set()),
 ("1,000",{"1000"}),
 ("0",set()),
 ("품목 1,980 1 1,980",{"1980"}),
 ("NO NUMBERS",set()),
 ("입금 12,00",set()),
 ("금액 +9876",{"9876"}),
 ("A1234B5678",{"1234","5678"}),
 ("𐌰1,234",{"1234"}),
 ("한글6789",{"6789"}),
)
@pytest.mark.parametrize(("raw","expected"),CASES,
 ids=[f"numeric-boundary-{i+1:02}" for i in range(len(CASES))])
def test_numeric_token_boundaries(raw,expected):
    assert numeric_candidates(raw)==expected

def test_non_string_inputs_and_output_size_fail_closed():
    assert numeric_candidates(None)==set()
    assert numeric_candidates(9999)==set()
    assert numeric_candidates("9"*20_001)==set()

def test_real_dataset_is_bounded_and_named():
    assert len(SAMPLES)==2
    assert all(name.startswith("IMG") and len(sha)==40 for name,sha,_,_ in SAMPLES)
    assert ACK=="RESEARCH_ONLY_PUBLIC_KORIE_TWO_SAMPLES"
