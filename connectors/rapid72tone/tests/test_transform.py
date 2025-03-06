import pytest
import responses
from tenable.io.sync.models.cve_finding import CVEFinding
from tenable.io.sync.models.device_asset import DeviceAsset

from rapid7.transform import Transformer


@pytest.fixture
def transformer(rsapi, tapi):
    return Transformer(db_uri='sqlite:///:memory:', rapid7=rsapi, tvm=tapi)


def test_get_network_info(transformer):
    ip_addresses = [
        {'ip': '10.50.1.159', 'mac': '00:50:56:92:E3:2B'},
        {'ip': '10.50.5.237', 'mac': '00:50:56:83:8B:9E'},
    ]

    network_info = transformer.get_network_info(ip_addresses)
    assert compare_lists(network_info['ipv4'], ['10.50.1.159', '10.50.5.237'])
    assert network_info['ipv6'] == []
    assert compare_lists(
        network_info['macs'], ['00:50:56:92:e3:2b', '00:50:56:83:8b:9e']
    )


def test_derive_system_type(transformer, linux_os, windows_os, unknown_os):
    assert transformer.derive_system_type(linux_os) == 'LINUX'
    assert transformer.derive_system_type(windows_os) == 'WINDOWS'
    assert transformer.derive_system_type(unknown_os) == 'UNKNOWN'


def compare_dicts(dict1, dict2) -> bool:
    """Compare two dictionaries recursively."""
    if dict1.keys() != dict2.keys():
        return False

    for key in dict1:
        if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            if not compare_dicts(dict1[key], dict2[key]):
                return False
        elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
            if not compare_lists(dict1[key], dict2[key], True):
                return False
        elif dict1[key] != dict2[key]:
            return False

    return True


def compare_lists(list1, list2, key_to_compare=None) -> bool:
    """Comapre two lists recursively."""
    if len(list1) != len(list2):
        return False

    # Check if the list contains dictionaries
    if isinstance(list1[0], dict) and isinstance(list2[0], dict):
        # For lists of dictionaries, compare based on a specific key if provided
        if key_to_compare:
            # Compare using the specified key from each dictionary
            list1_values = sorted(
                [item.get(key_to_compare) for item in list1 if key_to_compare in item]
            )
            list2_values = sorted(
                [item.get(key_to_compare) for item in list2 if key_to_compare in item]
            )
            return list1_values == list2_values
        else:
            # If no key is provided, compare all dictionary fields
            return sorted(list1) == sorted(list2)
    else:
        # For regular lists (not dictionaries), compare them directly
        return sorted(list1) == sorted(list2)


def test_transform_asset(transformer, asset):
    asset_data = {
        'object_type': 'device-asset',
        'asset_class': 'DEVICE',
        'device': {
            'networking': {
                'ip_addresses_v4': [{'address': '10.50.10.217'}],
                'mac_addresses': ['00:50:56:83:52:0e'],
            },
            'operating_system': {
                'confidence': 75,
                'type': 'LINUX',
            },
        },
        'id': '1',
    }
    asset_details = transformer.transform_asset(asset)
    resp = DeviceAsset(**asset_details).model_dump(mode='json', exclude_none=True)
    print(resp)
    assert compare_dicts(resp, asset_data)


@responses.activate
def test_transform_findings(transformer, asset_vuln, vuln_info, asset_id, kbs_page):
    responses.get('https://10.50.12.188:3780/api/3/vulnerabilities', json=kbs_page)
    vuln_data = {
        'object_type': 'cve-finding',
        'asset_id': '1',
        'cve': {'cves': ['CVE-2024-6387']},
        'definition_urn': 'urn:rapid7:openbsd-openssh-cve-2024-6387',
        'discovery': {'first_observed_at': '2025-02-12T11:04:29.692000Z'},
        'id': 'b28181db3212d164037184ae23500e47ab393c41c5d20a5025087962af71f604',
        'state': 'ACTIVE',
        'exposure': {'severity': {'level': 'CRITICAL'}},
    }
    transformer.cache_knowledgebase()
    vuln = transformer.transform_finding(asset_vuln, asset_id)
    resp = CVEFinding(**vuln).model_dump(mode='json', exclude_none=True)
    print(resp)
    assert compare_dicts(resp, vuln_data)
