"""CWE and CAPEC XML parsing (namespaced catalogs, dedupe, text cleanup)."""

from vuln2action.connectors.mitre import parse_capec_xml, parse_cwe_xml

CWE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.13">
  <Weaknesses>
    <Weakness ID="79" Name="Improper Neutralization of Input">
      <Description>Improper   neutralisation
      of input during web page generation.</Description>
    </Weakness>
    <Weakness ID="79" Name="Duplicate">
      <Description>duplicate entry</Description>
    </Weakness>
    <Weakness ID="89" Name="SQL Injection">
      <Description>Improper neutralisation of SQL elements.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""

CAPEC_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection">
      <Description>An attacker   injects SQL.</Description>
    </Attack_Pattern>
    <Attack_Pattern ID="66" Name="Duplicate">
      <Description>duplicate</Description>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


def test_parse_cwe_xml_strips_namespace_and_dedupes():
    records = parse_cwe_xml(CWE_XML)
    assert [record.cwe_id for record in records] == ["CWE-79", "CWE-89"]
    assert records[0].name == "Improper Neutralization of Input"
    assert records[0].description == "Improper neutralisation of input during web page generation."


def test_parse_capec_xml_normalises_ids():
    records = parse_capec_xml(CAPEC_XML)
    assert [record.capec_id for record in records] == ["CAPEC-66"]
    assert records[0].description == "An attacker injects SQL."


def test_parsers_accept_paths(tmp_path):
    cwe_path = tmp_path / "cwe.xml"
    cwe_path.write_text(CWE_XML, encoding="utf-8")
    capec_path = tmp_path / "capec.xml"
    capec_path.write_text(CAPEC_XML, encoding="utf-8")
    assert len(parse_cwe_xml(cwe_path)) == 2
    assert len(parse_capec_xml(capec_path)) == 1


def test_parsers_accept_bytes():
    assert len(parse_cwe_xml(CWE_XML.encode("utf-8"))) == 2
