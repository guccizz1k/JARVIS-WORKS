"""Focused J3/J6 regression tests for the J1–J6 integrated suite evidence gate."""
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree
import pytest

from scripts.jw_integrated_acceptance import audit_junit, validate_receipts, REQUIRED_DOMAINS

SHA="c"*40


def valid_receipts():
    return {"commit":SHA, "checks":[{"id":x,"status":"PASS","synthetic":True,"proof":"verified-url"} for x in sorted(REQUIRED_DOMAINS)],
            "release":"BLOCKED","production_deployed":False}


def test_receipt_complete_contract_is_valid():
    assert validate_receipts(valid_receipts(),SHA)==[]


@pytest.mark.parametrize("mutator",[
    lambda a:a.update(release="PASS"),
    lambda a:a.update(production_deployed=True),
    lambda a:a.update(commit="different"),
    lambda a:a["checks"].pop(),
    lambda a:a["checks"].append(a["checks"][0]),
    lambda a:a["checks"][0].update(status="NOT RUN"),
    lambda a:a["checks"][0].update(synthetic=False),
    lambda a:a["checks"][0].update(proof=""),
])
def test_unverified_or_missing_receipt_blocked(mutator):
    record=valid_receipts()
    mutator(record)
    assert validate_receipts(record,SHA)


def _junit(path,legacy,j6,fail=False,skip=False):
    root=Element("testsuite")
    for i in range(legacy):
        name=("test_pg_auth_v85" if i==0 else "test_pg_v90_integrated_entry" if i==1
              else "test_release_gate_v75" if i==2 else "tests.test_legacy")
        t=SubElement(root,"testcase",classname=name,name=f"test_case_{i}")
        if i==3 and fail:SubElement(t,"failure",message="broken")
        if i==4 and skip:SubElement(t,"skipped")
    for i in range(j6):
        name="test_jw_evidence_gate" if i<24 else "test_j6_postgres_restore"
        SubElement(root,"testcase",classname=name,name=f"test_j6_{i}")
    ElementTree(root).write(path,encoding="utf-8")


def test_real_junit_structure_accepts_589_plus_43(tmp_path):
    file=tmp_path/"all.xml"
    _junit(file,589,43)
    assert audit_junit(file)["passed"]==632


@pytest.mark.parametrize("legacy,j6",[(588,43),(589,42)])
def test_regression_minimum_catches_missing_cases(tmp_path,legacy,j6):
    file=tmp_path/"missing.xml"
    _junit(file,legacy,j6)
    with pytest.raises(AssertionError,match="coverage dropped"):
        audit_junit(file)


@pytest.mark.parametrize("fail,skip",[(True,False),(False,True)])
def test_failed_or_skipped_xml_must_block(tmp_path,fail,skip):
    file=tmp_path/"failed.xml"
    _junit(file,589,43,fail,skip)
    with pytest.raises(AssertionError,match="failed, errored, or skipped"):
        audit_junit(file)


def test_missing_required_module_blocks(tmp_path):
    file=tmp_path/"all.xml"
    _junit(file,589,43)
    root=ElementTree()
    root.parse(file)
    for case in root.getroot().findall("testcase"):
        if case.attrib["classname"]=="test_release_gate_v75":
            case.set("classname","tests.test_legacy")
    root.write(file)
    with pytest.raises(AssertionError,match="Mandatory module absent"):
        audit_junit(file)
