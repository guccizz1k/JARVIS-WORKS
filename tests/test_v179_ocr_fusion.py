"""V17.9 field selection: 36 adversarial deterministic oracle cases.

No raw OCR output, business ID, or personally identifying scan leaves CI.
Tests prove abstention on inconsistent amounts, not real OCR accuracy.
"""
import pytest
from scripts.ci_v179_ocr_multiview import fused, _image
from PIL import Image

@pytest.mark.parametrize(("raw","contrast","binary","expected"),[
    ({},{},{},{}),
    ({},{"total_amount":"7700"},{},{"total_amount":"7700"}),
    ({"total_amount":"7700"},{},{},{"total_amount":"7700"}),
    ({"total_amount":"7700"},{"total_amount":"7700"},{},{"total_amount":"7700"}),
    ({"total_amount":"7700"},{"total_amount":"7701"},{},{}),
    ({"total_amount":"0"},{"total_amount":"1"},{},{}),
    ({},{},{"total_amount":"99999999"},{}),
    ({"total_amount":"7700"},{},{"total_amount":"100"}, {"total_amount":"7700"}),
    ({},{},{"counterparty":"한빛"},{"counterparty":"한빛"}),
    ({"counterparty":"wrong"},{},{"counterparty":"correct"},{"counterparty":"correct"}),
    ({},{"counterparty":"wrong"},{"counterparty":"correct"},{"counterparty":"correct"}),
    ({},{},{"business_number":"1234567890"},{"business_number":"1234567890"}),
    ({"business_number":"0000000000"},{},{"business_number":"1234567890"},{"business_number":"1234567890"}),
    ({"total_amount":"7700"},{"total_amount":"7701"},{"counterparty":"good"},{"counterparty":"good"}),
    ({"total_amount":"7700"},{"total_amount":"7700"},{"counterparty":"good","business_number":"1234567890"},{"counterparty":"good","business_number":"1234567890","total_amount":"7700"}),
    ({"total_amount":"1000"},{"total_amount":"1000"},{"total_amount":"9999","business_number":"1234567890"},{"business_number":"1234567890","total_amount":"1000"}),
    ({"counterparty":"bad","total_amount":"1000"},{"total_amount":"1000"},{"counterparty":"good"},{"counterparty":"good","total_amount":"1000"}),
    ({"total_amount":"1000"},{"total_amount":"1001"},{"counterparty":"good"},{"counterparty":"good"}),
    ({"total_amount":"1"},{"total_amount":"2"},{"total_amount":"3"},{}),
    ({"total_amount":"1"},{"total_amount":"1"},{"total_amount":"2"},{"total_amount":"1"}),
    ({},{},{"counterparty":"A","business_number":"B"},{"counterparty":"A","business_number":"B"}),
    ({"total_amount":"10"},{},{"business_number":"B"},{"business_number":"B","total_amount":"10"}),
    ({"total_amount":"10"},{"total_amount":"11"},{"business_number":"B"},{"business_number":"B"}),
    ({},{},{"counterparty":"A","business_number":"B","total_amount":"1"},{"counterparty":"A","business_number":"B"}),
    ({"total_amount":"100"},{},{"counterparty":"X","business_number":"B"},{"counterparty":"X","business_number":"B","total_amount":"100"}),
    ({"total_amount":"100"},{"total_amount":"100"},{"counterparty":"X","business_number":"B"},{"counterparty":"X","business_number":"B","total_amount":"100"}),
    ({"total_amount":"100"},{"total_amount":"100"},{"counterparty":"X","business_number":"B","total_amount":"999"},{"counterparty":"X","business_number":"B","total_amount":"100"}),
    ({"total_amount":"900"},{"total_amount":"901"},{"counterparty":"X","business_number":"B","total_amount":"900"},{"counterparty":"X","business_number":"B"}),
    ({"counterparty":"Y"},{},{"counterparty":"X"},{"counterparty":"X"}),
    ({"business_number":"Y"},{},{"business_number":"X"},{"business_number":"X"}),
    ({"counterparty":"Y"},{"counterparty":"Z"},{"counterparty":"X"},{"counterparty":"X"}),
    ({"business_number":"Y"},{"business_number":"Z"},{"business_number":"X"},{"business_number":"X"}),
    ({"total_amount":"100"},{"total_amount":"100"},{},{"total_amount":"100"}),
    ({"total_amount":"100"},{"total_amount":"101"},{},{}),
    ({},{"total_amount":"101"},{"total_amount":"100"},{"total_amount":"101"}),
    ({"total_amount":"100"},{},{"total_amount":"101"},{"total_amount":"100"}),
])
def test_36_multiview_adversarial_cases(raw,contrast,binary,expected):
    assert fused(raw,contrast,binary)==expected

@pytest.mark.parametrize("name",["raw","autocontrast","binary"])
def test_expected_modes_only(name):
    pic=_image(Image.new("RGB",(10,10),"white"),name)
    assert pic.size==(20,20) if name=="binary" else pic.size==(10,10)

def test_unexpected_preprocessing_mode_rejected():
    with pytest.raises(ValueError):
        _image(Image.new("RGB",(10,10),"white"),"auto_approve_customer")
