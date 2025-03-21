import pytest
from tenable.io.sync.models.cve_finding import CVEFinding
from tenable.io.sync.models.device_asset import DeviceAsset
from carbonblack.transform import Transformer
from ipaddress import ip_address


@pytest.fixture
def transformer(cba, tapi):
    return Transformer(cba=cba, tvm=tapi)


class JobManager:
    counters = {'device-asset': {'accepted': 15}, 'cve-finding': {'accepted': 20}}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass


def test_transform_asset(transformer, asset_details):
    tnx_asset = {
        'object_type': 'device-asset',
        'asset_class': 'DEVICE',
        'id': '6697325',
        'name': 'cayenne',
        'device': {
            'networking': {
                'ip_addresses_v4': [
                    {
                        'address': '192.168.38.251',
                    }
                ],
                'mac_addresses': ['06:2b:5b:41:2d:99'],
            },
            'operating_system': {
                'product': {'version': 'ubuntu 22.04.1 x64', 'product_name': 'linux'},
                'type': 'LINUX',
            },
            'system_type': 'aws',
        },
        'exposure': {'criticality': {'level': 'MEDIUM'}},
    }

    asset = transformer.transform_asset(asset_details)
    assert DeviceAsset(**asset).model_dump(mode='json', exclude_none=True) == tnx_asset


def test_transform_finding(transformer, finding_details):
    asset = 'ip-172-31-87-51.ec2.internal'
    tnx_finding = {
        'object_type': 'cve-finding',
        'asset_id': asset,
        'id': 'CVE-2009-5155',
        'definition_urn': 'urn:carbonblack:CVE-2009-5155',
        'cve': {'cves': ['CVE-2009-5155']},
        'observations': {
            'software': [
                {
                    'product': {
                        'product_name': 'glibc',
                        'vendor_name': 'amazon linux',
                        'version': '2.26',
                    }
                }
            ],
        },
        'exposure': {'severity': {'level': 'LOW'}},
        'state': 'ACTIVE',
    }

    finding = transformer.transform_finding(finding_details, asset)
    assert (
        CVEFinding(**finding).model_dump(mode='json', exclude_none=True) == tnx_finding
    )


def test_derive_system_type(transformer):
    system_type = {
        'WINDOWS': 'WINDOWS',
        'LINUX': 'LINUX',
        'mac': 'MAC_OS',
        'OTHER': 'UNKNOWN',
    }
    for key in system_type:
        assert transformer.derive_system_type(key) == system_type[key]


def test_derive_severity(transformer):
    severity = {
        'critical': 'CRITICAL',
        'MODERATE': 'MEDIUM',
        'IMPORTANT': 'HIGH',
        'LOW': 'LOW',
        'MINOR': 'NONE',
    }
    for key in severity:
        assert transformer.derive_severity(key) == severity[key]


def test_format_mac_address(transformer):
    assert transformer.format_mac_address('062b5b412d99') == ['06:2b:5b:41:2d:99']
    assert transformer.format_mac_address(None) is None


def test_validate_ip_address(transformer):
    assert transformer.validate_ip_address('192.168.38.251') == [
        {'address': ip_address('192.168.38.251')}
    ]
    assert transformer.validate_ip_address(
        '1050:0000:0000:0000:0005:0600:300c:326b', is_ipv4=False
    ) == [{'address': ip_address('1050:0000:0000:0000:0005:0600:300c:326b')}]
    assert transformer.validate_ip_address(None, is_ipv4=True) is None
