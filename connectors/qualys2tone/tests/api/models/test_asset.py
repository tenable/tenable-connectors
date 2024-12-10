from datetime import UTC, datetime

from qualys.api.models.asset import (
    DnsData,
    Host,
    Tag,
    TruriskScoreFactors,
    TruriskSeverityCount,
)


def test_truriskseveritycount():
    xml = """
    <VULN_COUNT qds_severity="3">50</VULN_COUNT>
    """
    obj = TruriskSeverityCount.from_xml(xml)
    assert obj.severity == 3
    assert obj.count == 50


def test_truriskscorefactors():
    xml = """
    <TRURISK_SCORE_FACTORS>
      <TRURISK_SCORE_FORMULA>test_formula</TRURISK_SCORE_FORMULA>
      <VULN_COUNT qds_severity="1">0</VULN_COUNT>
      <VULN_COUNT qds_severity="2">10</VULN_COUNT>
      <VULN_COUNT qds_severity="3">20</VULN_COUNT>
      <VULN_COUNT qds_severity="4">30</VULN_COUNT>
      <VULN_COUNT qds_severity="5">40</VULN_COUNT>
    </TRURISK_SCORE_FACTORS>
    """
    obj = TruriskScoreFactors.from_xml(xml)
    assert obj.formula == 'test_formula'
    assert obj.counts[0].severity == 1
    assert obj.counts[0].count == 0
    assert obj.counts[-1].severity == 5
    assert obj.counts[-1].count == 40


def test_dnsdata():
    xml = """
    <DNS_DATA>
      <HOSTNAME><![CDATA[remote]]></HOSTNAME>
      <DOMAIN><![CDATA[nowhere.com]]></DOMAIN>
      <FQDN><![CDATA[remote.nowhere.com]]></FQDN>
    </DNS_DATA>  
    """
    obj = DnsData.from_xml(xml)
    assert obj.hostname == 'remote'
    assert obj.domain == 'nowhere.com'
    assert obj.fqdn == 'remote.nowhere.com'


def test_tag_lists():
    xml = """
    <TAG>
      <TAG_ID><![CDATA[123456]]></TAG_ID>
      <NAME><![CDATA[test]]></NAME>
    </TAG>
    """
    obj = Tag.from_xml(xml)
    assert obj.id == 123456
    assert obj.name == 'test'


def test_host():
    xml = """
    <HOST>
      <ID>12345</ID>
      <ASSET_ID>23456</ASSET_ID>
      <IP>1.2.3.4</IP>
      <ASSET_RISK_SCORE>352</ASSET_RISK_SCORE>
      <TRURISK_SCORE>352</TRURISK_SCORE>
      <TRURISK_SCORE_FACTORS>
        <TRURISK_SCORE_FORMULA></TRURISK_SCORE_FORMULA>
        <VULN_COUNT qds_severity="1">10</VULN_COUNT>
        <VULN_COUNT qds_severity="2">20</VULN_COUNT>
        <VULN_COUNT qds_severity="3">30</VULN_COUNT>
        <VULN_COUNT qds_severity="4">40</VULN_COUNT>
        <VULN_COUNT qds_severity="5">50</VULN_COUNT>
      </TRURISK_SCORE_FACTORS>
      <TRACKING_METHOD>CloudAgent</TRACKING_METHOD>
      <DNS><![CDATA[remote.example.com]]></DNS>
      <DNS_DATA>
        <HOSTNAME><![CDATA[remote]]></HOSTNAME>
        <DOMAIN><![CDATA[example.com]]></DOMAIN>
        <FQDN><![CDATA[remote.example.com]]></FQDN>
      </DNS_DATA>
      <NETBIOS><![CDATA[REMOTE]]></NETBIOS>
      <OS><![CDATA[Windows Vista / Windows 2008 / Windows 7 / Windows 2012]]></OS>
      <QG_HOSTID><![CDATA[f22a9bb9-2311-4170-80fa-c62bddd2dc86]]></QG_HOSTID>
      <LAST_BOOT>2024-02-20T18:29:08Z</LAST_BOOT>
      <SERIAL_NUMBER><![CDATA[VMware-56 4d d2 32 1b d5 ba 19-0c 78 86 69 8b e1 40 35]]></SERIAL_NUMBER>
      <HARDWARE_UUID><![CDATA[32d24d56-d51b-19ba-0c78-86698be14035]]></HARDWARE_UUID>
      <FIRST_FOUND_DATE>2020-07-28T14:35:14Z</FIRST_FOUND_DATE>
      <LAST_ACTIVITY>2024-03-05T08:02:56Z</LAST_ACTIVITY>
      <AGENT_STATUS><![CDATA[Inventory Scan Complete]]></AGENT_STATUS>
      <CLOUD_AGENT_RUNNING_ON><![CDATA[QAGENT]]></CLOUD_AGENT_RUNNING_ON>
      <TAGS>
        <TAG>
          <TAG_ID><![CDATA[1234567890]]></TAG_ID>
          <NAME><![CDATA[example_tag]]></NAME>
        </TAG>
      </TAGS>
    </HOST>
    """

    obj = Host.from_xml(xml)
    assert obj.id == 12345
    assert obj.asset_id == 23456
    assert obj.asset_risk_score == 352
    assert obj.trurisk_score == 352
    assert obj.trurisk.formula is None
    assert str(obj.ip) == '1.2.3.4'
    assert obj.ipv6 is None
    assert obj.dns == 'remote.example.com'
    assert obj.dns_data.hostname == 'remote'
    assert obj.dns_data.domain == 'example.com'
    assert obj.dns_data.fqdn == 'remote.example.com'
    assert obj.netbios == 'REMOTE'
    assert obj.os == 'Windows Vista / Windows 2008 / Windows 7 / Windows 2012'
    assert obj.qg_hostid == 'f22a9bb9-2311-4170-80fa-c62bddd2dc86'
    assert obj.last_boot == datetime(2024, 2, 20, 18, 29, 8, tzinfo=UTC)
    assert obj.last_activity == datetime(2024, 3, 5, 8, 2, 56, tzinfo=UTC)
    assert obj.first_found_date == datetime(2020, 7, 28, 14, 35, 14, tzinfo=UTC)
    assert obj.hardware_uuid == '32d24d56-d51b-19ba-0c78-86698be14035'
    assert obj.serial_number == 'VMware-56 4d d2 32 1b d5 ba 19-0c 78 86 69 8b e1 40 35'
