import pytest
from tenable.io.sync.models.cve_finding import CVEFinding
from tenable.io.sync.models.device_asset import DeviceAsset

from crowdstrike.transform import Transformer


@pytest.fixture
def transformer(csapi, tapi):
    return Transformer(crwd=csapi, tvm=tapi)


def compare_dicts(dict1, dict2) -> bool:
    """Compare tow dictionaries recursively."""
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


def compare_lists(list1, list2, key_to_compare=None):
    """
    Compare lists, handling lists of dictionaries
    (e.g., ip_addresses_v4) and regular lists.
    """
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


def test_transform_asset(transformer, asset_details):
    tnx_asset = {
        'device': {
            'hardware': {
                'bios': {
                    'manufacturer': 'amazon ec2',
                    'version': '1.0',
                },
                'serial_number': 'ec2d9982-1ab8-cfb5-552b-34c568a57fc9',
            },
            'networking': {
                'ip_addresses_v4': [{'address': '8.8.8.8'}, {'address': '172.1.1.2'}],
                'mac_addresses': ['6e:61:0e:cb:da:68'],
            },
            'operating_system': {
                'type': 'LINUX',
            },
        },
        'discovery': {
            'assessment_status': 'SKIPPED_FINDINGS',
            'first_observed_on': '2024-12-08T00:05:01Z',
            'last_observed_on': '2024-12-08T00:05:01Z',
        },
        'labels': [
            'SensorGroupingTags/CloudSecurity',
            'SensorGroupingTags/DevUse2Dep3Eks1Backend',
        ],
        'id': '11111111111',
        'external_ids': [{'qualifier': 'crowdstrike-agent-id', 'value': '11111111111'}],
        'name': 'ip-10-1-1-2.us-east-2.compute.internal',
        'object_type': 'device-asset',
        'asset_class': 'DEVICE',
    }

    t = transformer.transform_asset(asset_details)
    a = DeviceAsset(**t).model_dump(mode='json', exclude_none=True)
    assert compare_dicts(a, tnx_asset)


def test_transform_finding(transformer, finding_details):
    tnx_finding = {
        'object_type': 'cve-finding',
        'asset_id': '897580de18',
        'definition_urn': 'urn:crowdstrike:CVE-2024-50222',
        'state': 'ACTIVE',
        'discovery': {
            'first_observed_at': '2025-01-09T09:12:55Z',
            'last_observed_on': '2025-02-21T00:48:53Z',
        },
        'id': '897580',
        'cve': {'cves': ['CVE-2024-50222']},
        'observations': {
            'software': [
                {
                    'product': {
                        'product_name': 'Ubuntu',
                        'vendor_name': 'linux-signed 6.8.0-51.52',
                        'version': 'linux-signed',
                    }
                }
            ]
        },
        'exposure': {'severity': {'level': 'HIGH'}},
    }

    finding = transformer.transform_finding(finding_details)
    f = CVEFinding(**finding).model_dump(mode='json', exclude_none=True)
    assert compare_dicts(f, tnx_finding)


def test_derive_system_type(transformer):
    assert transformer.derive_system_type('windows2022') == 'WINDOWS'
    assert transformer.derive_system_type('linux') == 'LINUX'
    assert transformer.derive_system_type('macos') == 'MAC_OS'
    assert transformer.derive_system_type('centos') == 'UNKNOWN'
