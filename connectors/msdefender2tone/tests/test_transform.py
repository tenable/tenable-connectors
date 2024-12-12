import pytest
from tenable.io.sync.models.cve_finding import CVEFinding
from tenable.io.sync.models.device_asset import DeviceAsset

from msdefender.transform import Transformer


@pytest.fixture
def transformer(msdapi, tapi):
    return Transformer(defender=msdapi, tvm=tapi)


def test_transform_asset(transformer, asset):
    tnx_asset = {
        'device': {
            'networking': {
                'fqdns': [{'value': 'tar-oracle-9.labnet.local'}],
                'ip_addresses_v4': [
                    {'address': '192.168.1.42'},
                    {'address': '100.16.206.202'},
                ],
                'mac_addresses': [
                    '00:50:56:ab:d6:4c',
                ],
            },
            'operating_system': {
                'build': 'None',
                'product': {
                    'product_name': 'oraclelinux',
                    'version': '9.0',
                },
                'type': 'UNKNOWN',
            },
        },
        'discovery': {
            'first_observed_at': '2024-07-25T12:59:25.383557Z',
            'last_observed_on': '2024-12-07T23:33:15.872995Z',
        },
        'exposure': {
            'criticality': {'level': 'MEDIUM'},
        },
        'id': '080eaae77b6953abe2dbb471cc749baba40b040f',
        'name': 'tar-oracle-9.labnet.local',
        'object_type': 'device-asset',
        'asset_class': 'DEVICE',
    }

    asset = transformer.transform_asset(asset)
    assert DeviceAsset(**asset).model_dump(exclude_none=True, mode='json') == tnx_asset


def test_transform_finding(transformer, vuln):
    tnx_finding = {
        'asset_id': '24f7e1b0edb56c2952eff253eca1428586057dbf',
        'cve': {'cves': ['CVE-2024-9936']},
        'exposure': {'severity': {'level': 'MEDIUM'}},
        'observations': {
            'software': [
                {
                    'product': {
                        'product_name': 'firefox',
                        'vendor_name': 'mozilla',
                        'version': '83.0.0.0',
                    },
                }
            ],
        },
        'id': '57b71605-b27e-3401-a3fc-b000e869051c',
        'object_type': 'cve-finding',
    }

    finding = transformer.transform_finding(vuln)
    assert (
        CVEFinding(**finding).model_dump(exclude_none=True, mode='json') == tnx_finding
    )
