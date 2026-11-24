import xml.etree.ElementTree as ET
import pytest
from scripts import jw_main_ci_receipt as m


def report():
    root = ET.Element('testsuites')
    suite = ET.SubElement(root, 'testsuite', tests=str(sum(m.MINIMUMS.values())), failures='0', errors='0', skipped='0')
    for module, n in m.MINIMUMS.items():
        for i in range(n):
            ET.SubElement(suite, 'testcase', classname='tests.'+module, name='test_'+str(i))
    return root, suite


def test_complete():
    root, _ = report()
    assert m.verify(ET.tostring(root)) == sum(m.MINIMUMS.values())


@pytest.mark.parametrize('kind', ['failure','error','skipped'])
def test_case_not_pass(kind):
    root, suite = report()
    ET.SubElement(suite[0], kind)
    with pytest.raises(ValueError): m.verify(ET.tostring(root))


@pytest.mark.parametrize('kind', ['failures','errors','skipped','tests'])
def test_suite_not_pass(kind):
    root, suite = report()
    suite.set(kind, '1')
    with pytest.raises(ValueError): m.verify(ET.tostring(root))


def test_missing_module():
    root, suite = report()
    suite.remove(suite[0]); suite.set('tests',str(len(suite)))
    with pytest.raises(ValueError): m.verify(ET.tostring(root))


def test_duplicate():
    root, suite = report(); suite[1].set('name',suite[0].get('name'))
    with pytest.raises(ValueError): m.verify(ET.tostring(root))


@pytest.mark.parametrize('raw', [b'',b'<testsuites/>',b'<x/>',b'bad',b'<!DOCTYPE x><x/>',b' '*8388609])
def test_invalid(raw):
    with pytest.raises((ValueError,ET.ParseError)): m.verify(raw)
