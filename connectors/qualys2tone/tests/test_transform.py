from datetime import UTC, datetime

import pytest
import responses

from qualys.transform import Transformer


@pytest.fixture
def transformer(qapi, tapi):
    return Transformer(tvm=tapi, qualys=qapi, db_uri='sqlite:///:memory:')


def test_transformer_get_os_type(transformer):
    assert transformer.get_os_type('Windows XP') == 'WINDOWS'
    assert transformer.get_os_type('RedHat Enterprise Linux 8.0') == 'LINUX'
    assert transformer.get_os_type('Apple MacOS Yosemite') == 'MAC_OS'


def test_transformer_criticality_level(transformer):
    assert transformer.get_asset_criticality_level(900) == 'CRITICAL'
    assert transformer.get_asset_criticality_level(700) == 'HIGH'
    assert transformer.get_asset_criticality_level(500) == 'MEDIUM'
    assert transformer.get_asset_criticality_level(300) == 'LOW'


def test_asset_transformer(transformer):
    mock_asset = {
        'agent_status': 'Inventory Scan Complete',
        'asset_id': 12345,
        'asset_risk_score': 0,
        'cloud_agent_running_on': 'QAGENT',
        'dns': 'remote',
        'dns_data': {'hostname': 'remote'},
        'first_found_date': datetime(2023, 8, 3, 6, 9, 24, tzinfo=UTC),
        'hardware_uuid': '6DB24D56-DEAD-BEEF-0011-223344556677',
        'id': 23456,
        'ip': '1.2.3.4',
        'last_activity': datetime(2023, 9, 1, 18, 25, 20, tzinfo=UTC),
        'last_boot': datetime(2023, 8, 3, 12, 19, 41, tzinfo=UTC),
        'netbios': 'REMOTE',
        'os': 'Windows 10 Pro 64 bit Edition Version 21H2',
        'qg_hostid': '3cde24a7-aabb-ccdd-eeff-001122334455',
        'serial_number': 'VMware-dd ee aa dd bb ee ee ff-00 11 22 33 44 55 66 77',
        'tags': [
            {'id': 10091892, 'name': 'Cloud Agent'},
        ],
        'tracking_method': 'Cloud Agent',
        'trurisk': {
            'counts': [
                {'count': 0, 'severity': 1},
                {'count': 18, 'severity': 2},
                {'count': 11, 'severity': 3},
                {'count': 2, 'severity': 4},
                {'count': 21, 'severity': 5},
            ],
            'formula': '4 * '
            '{(1.0*0)*(0^0.01)+(0.6*0)*(0^0.01)+(0.4*0)*(0^0.01)+(0.2*0)*(0^0.01)}',
        },
        'trurisk_score': 0,
    }
    tnx_asset = {
        'object_type': 'device-asset',
        'asset_class': 'DEVICE',
        'id': '23456',
        'name': None,
        'device': {
            'hardware': {
                'bios': {'id': '6DB24D56-DEAD-BEEF-0011-223344556677'},
                'serial_number': 'VMware-dd ee aa dd bb ee ee ff-00 11 22 33 44 55 66 77',
            },
            'netbios_name': 'REMOTE',
            'networking': {
                'fqdns': [{'value': 'remote'}],
                'ip_addresses_v4': [{'address': '1.2.3.4'}],
                'ip_addresses_v6': None,
                'network_group_id': 'c0b418b7-e64c-4751-b287-b6e0d9a24010',
            },
            'operating_system': {'type': 'WINDOWS'},
        },
        'external_ids': [
            {
                'qualifier': 'qualys-agent-id',
                'value': '3cde24a7-aabb-ccdd-eeff-001122334455',
            },
        ],
        'discovery': {
            'authentication': {
                'attempted': False,
                'successful': False,
                'type': 'AGENT',
            },
            'assessment_status': 'ATTEMPTED_FINDINGS',
            'first_observed_on': datetime(2023, 8, 3, 6, 9, 24, tzinfo=UTC),
            'last_observed_on': None,
        },
        'labels': ['Cloud Agent'],
        'exposure': {'criticality': {'score': None, 'level': 'NONE'}},
    }
    assert transformer.transform_asset(mock_asset) == tnx_asset


@responses.activate
def test_transform_finding(transformer, kbs_page):
    responses.get('https://nourl.qualys/api/2.0/fo/knowledge_base/vuln/', body=kbs_page)
    asset_id = 12345678
    mock_finding = {
        'id': 123456789,
        'is_disabled': False,
        'is_ignored': False,
        'last_found': datetime(2023, 9, 2, 8, 0, 59, tzinfo=UTC),
        'last_processed': datetime(2023, 9, 2, 8, 4, 6, tzinfo=UTC),
        'last_test': datetime(2023, 9, 2, 8, 0, 59, tzinfo=UTC),
        'last_update': datetime(2023, 9, 2, 8, 4, 6, tzinfo=UTC),
        'qds': {'score': 50, 'severity': 'MEDIUM'},
        'qds_factors': [
            {'name': 'RTI', 'value': 'No_Patch,Easy_Exploit'},
            {'name': 'CVSS', 'value': '5.0'},
            {'name': 'CVSS_version', 'value': 'v2'},
            {'name': 'QID_severity', 'value': '2.0'},
        ],
        'qid': 6,
        'results': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon cachedlogonscount = 10',
        'severity': 2,
        'ssl': False,
        'status': 'Active',
        'times_found': 149,
        'type': 'Confirmed',
    }
    tnx_finding = {
        'asset_id': '12345678',
        'cve': {
            'cves': [
                'CVE-1999-0001',
            ],
        },
        'definition_urn': 'qualys:6',
        'discovery': {
            'first_observed_at': None,
            'last_observed_on': datetime(2023, 9, 2, 8, 0, 59, tzinfo=UTC),
        },
        'exposure': {
            'severity': {
                'level': 'LOW',
            },
        },
        'id': '123456789',
        'object_type': 'cve-finding',
        'state': 'ACTIVE',
    }
    transformer.cache_knowledgebase()
    assert transformer.transform_finding(mock_finding, asset_id) == tnx_finding
