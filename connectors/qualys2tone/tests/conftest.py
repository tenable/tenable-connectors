import pytest
from tenable.io import TenableIO

from qualys.api import QualysAPI


@pytest.fixture
def qapi():
    return QualysAPI(
        url='https://nourl.qualys',
        username='test_user',
        password='test_password',
    )


@pytest.fixture
def tapi():
    return TenableIO(
        url='https://nourl.tvm',
        access_key='something',
        secret_key='something',
    )


@pytest.fixture
def host():
    return """
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


@pytest.fixture
def asset_page(host):
    return f"""
    <HOST_LIST_OUTPUT>
      <RESPONSE>
        <DATETIME>2024-08-01T02:22:29Z</DATETIME>
        <HOST_LIST>
          {host}
        </HOST_LIST>
      </RESPONSE>
    </HOST_LIST_OUTPUT>
    """


@pytest.fixture
def asset_page_one(host):
    return f"""
    <HOST_LIST_OUTPUT>
      <RESPONSE>
        <DATETIME>2024-08-01T02:22:29Z</DATETIME>
        <HOST_LIST>
          {host}
        </HOST_LIST>
        <WARNING>
          <CODE>1980</CODE>
          <TEXT>This is some sample text</TEXT>
          <URL><![CDATA[https://nourl.com/]]></URL>
        </WARNING>
      </RESPONSE>
    </HOST_LIST_OUTPUT>
    """


@pytest.fixture
def asset_finding():
    return """
    <HOST>
      <ID>123456</ID>
      <ASSET_ID>234567</ASSET_ID>
      <IP>1.2.3.4</IP>
      <TRACKING_METHOD>IP</TRACKING_METHOD>
      <OS><![CDATA[Red Hat Enterprise Linux 8.0]]></OS>
      <OS_CPE><![CDATA[cpe:/o:redhat:enterprise_linux:8.0:::]]></OS_CPE>
      <LAST_SCAN_DATETIME>2023-08-10T13:45:17Z</LAST_SCAN_DATETIME>
      <LAST_VM_SCANNED_DATE>2023-08-10T13:23:13Z</LAST_VM_SCANNED_DATE>
      <LAST_VM_SCANNED_DURATION>922</LAST_VM_SCANNED_DURATION>
      <LAST_VM_AUTH_SCANNED_DATE>2023-08-10T13:23:13Z</LAST_VM_AUTH_SCANNED_DATE>
      <LAST_VM_AUTH_SCANNED_DURATION>922</LAST_VM_AUTH_SCANNED_DURATION>
      <TAGS>
        <TAG>
          <TAG_ID><![CDATA[12345]]></TAG_ID>
          <NAME><![CDATA[TagName]]></NAME>
        </TAG>
      </TAGS>
      <DETECTION_LIST>
        <DETECTION>
          <UNIQUE_VULN_ID>294650000</UNIQUE_VULN_ID>
          <QID>237189</QID>
          <TYPE>Confirmed</TYPE>
          <SEVERITY>5</SEVERITY>
          <SSL>0</SSL>
          <RESULTS><![CDATA[Package   Installed Version   Required Version firefox 60.5.1-1.el8.x86_64 60.6.1-1.el8]]></RESULTS>
          <STATUS>Active</STATUS>
          <FIRST_FOUND_DATETIME>2023-08-10T11:50:56Z</FIRST_FOUND_DATETIME>
          <LAST_FOUND_DATETIME>2023-08-10T13:23:13Z</LAST_FOUND_DATETIME>
          <QDS severity="HIGH">72</QDS>
          <QDS_FACTORS>
            <QDS_FACTOR name="RTI"><![CDATA[dos]]></QDS_FACTOR>
            <QDS_FACTOR name="exploit_maturity"><![CDATA[poc]]></QDS_FACTOR>
            <QDS_FACTOR name="CVSS"><![CDATA[9.8]]></QDS_FACTOR>
            <QDS_FACTOR name="CVSS_version"><![CDATA[v3.x]]></QDS_FACTOR>
            <QDS_FACTOR name="epss"><![CDATA[0.2054]]></QDS_FACTOR>
            <QDS_FACTOR name="trending"><![CDATA[07112024]]></QDS_FACTOR>
            <QDS_FACTOR name="CVSS_vector"><![CDATA[AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]]></QDS_FACTOR>
          </QDS_FACTORS>
          <TIMES_FOUND>2</TIMES_FOUND>
          <LAST_TEST_DATETIME>2023-08-10T13:23:13Z</LAST_TEST_DATETIME>
          <LAST_UPDATE_DATETIME>2023-08-10T13:45:17Z</LAST_UPDATE_DATETIME>
          <IS_IGNORED>0</IS_IGNORED>
          <IS_DISABLED>0</IS_DISABLED>
          <LAST_PROCESSED_DATETIME>2023-08-10T13:45:17Z</LAST_PROCESSED_DATETIME>
        </DETECTION>
      </DETECTION_LIST>
    </HOST>
    """


@pytest.fixture
def findings_page(asset_finding):
    return f"""
    <HOST_LIST_VM_DETECTION>
      <RESPONSE>
        <DATETIME>2024-08-01T02:22:29Z</DATETIME>
        <HOST_LIST>
          {asset_finding}
        </HOST_LIST>
      </RESPONSE>
    </HOST_LIST_VM_DETECTION>
    """


@pytest.fixture
def kbs_page():
    return """
    <KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
      <RESPONSE>
        <DATETIME>2024-10-31T16:22:39Z</DATETIME>
        <VULN_LIST>
          <VULN>
            <QID>6</QID>
            <VULN_TYPE>Information Gathered</VULN_TYPE>
            <SEVERITY_LEVEL>1</SEVERITY_LEVEL>
            <TITLE><![CDATA[DNS Host Name]]></TITLE>
            <CATEGORY>Information gathering</CATEGORY>
            <LAST_SERVICE_MODIFICATION_DATETIME>2018-01-04T17:39:37Z</LAST_SERVICE_MODIFICATION_DATETIME>
            <PUBLISHED_DATETIME>1999-01-01T08:00:00Z</PUBLISHED_DATETIME>
            <PATCHABLE>0</PATCHABLE>
            <SOFTWARE_LIST>
              <SOFTWARE>
                <PRODUCT><![CDATA[dns_server]]></PRODUCT>
                <VENDOR><![CDATA[none]]></VENDOR>
              </SOFTWARE>
            </SOFTWARE_LIST>
            <CVE_LIST>
              <CVE>
                <ID>CVE-1999-0001</ID>
                <URL>abcdef</URL>
              </CVE>
            </CVE_LIST>
            <DIAGNOSIS><![CDATA[The fully qualified domain name of this host, if it was obtained from a DNS server, is displayed in the RESULT section.]]></DIAGNOSIS>
            <PCI_FLAG>0</PCI_FLAG>
            <DISCOVERY>
              <REMOTE>1</REMOTE>
            </DISCOVERY>
          </VULN>
        </VULN_LIST>
      </RESPONSE>
    </KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
    """
