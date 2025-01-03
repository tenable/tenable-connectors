from datetime import UTC, datetime

import pytest
import responses
from tenable.io.sync.models.device_asset import DeviceAsset

from sentinelone.transform import Transformer


@pytest.fixture
def transformer(s1api, tapi):
    return Transformer(tvm=tapi, s1=s1api)


def test_transformer_get_os_type(transformer):
    assert transformer.get_os_type('Windows XP') == 'WINDOWS'
    assert transformer.get_os_type('RedHat Enterprise Linux 8.0') == 'LINUX'
    assert transformer.get_os_type('Apple MacOS Yosemite') == 'MAC_OS'


def test_asset_transformer(transformer, agent):
    asset = transformer.asset_transformer(agent)
    resp = DeviceAsset(**asset).model_dump(mode='json', exclude_none=True)
    assert resp['device']['hardware'] == {
        'cpu': {
            'count': 2,
            'name': 'Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz',
        },
        'model': 'Xen HVM domU',
        'ram_mb': 3904,
    }
    assert resp['device']['operating_system'] == {
        'build': 'Ubuntu 22.04.4 LTS 6.5.0-1022-aws',
        'product': {
            'product_name': 'linux',
        },
        'type': 'LINUX',
    }
    assert resp['discovery'] == {
        'authentication': {
            'attempted': True,
            'successful': True,
            'type': 'AGENT',
        },
        'first_observed_at': '2024-08-07T17:57:08.475617Z',
        'last_observed_on': '2024-12-06T03:43:42.885065Z',
    }
    assert resp['tags'] == [{'name': 'test', 'value': 'value'}]
    assert {'address': '172.31.4.242'} in resp['device']['networking'][
        'ip_addresses_v4'
    ]
    assert {'address': '35.89.96.104'} in resp['device']['networking'][
        'ip_addresses_v4'
    ]
    assert {'address': 'fe80::887:7aff:fe4f:b40b'} in resp['device']['networking'][
        'ip_addresses_v6'
    ]
    assert resp['device']['networking']['mac_addresses'] == ['0a:87:7a:4f:b4:0b']
    assert resp['id'] == '2011794797031672400'
    assert resp['name'] == 'ip-172-31-4-242'


def test_finding_transformer(transformer, app):
    finding = transformer.finding_transformer(app, ['CVE-2012-6655'], severity=3)
    assert finding == {
        'object_type': 'cve-finding',
        'state': 'ACTIVE',
        'cve': {'cves': ['CVE-2012-6655']},
        'exposure': {'severity': {'level': 'MEDIUM'}},
    }


@responses.activate
def test_get_cves(transformer, cve_page):
    responses.get(
        'https://nourl.s1/web/api/v2.1/application-management/risks/cves', json=cve_page
    )
    assert transformer.get_cves(1) == (['CVE-2012-6655'], 2)


def test_finding_endpoint_transformer(transformer, app, endpoint):
    base_finding = transformer.finding_transformer(app, ['CVE-2012-6655'], 3)
    finding = transformer.finding_endpoint_transformer(base_finding, endpoint)
    assert finding == {
        'object_type': 'cve-finding',
        'state': 'ACTIVE',
        'cve': {'cves': ['CVE-2012-6655']},
        'exposure': {'severity': {'level': 'MEDIUM'}},
        'asset_id': '2011957903825504800',
        'discovery': {
            'first_observed_at': datetime(2024, 8, 14, 21, 37, 26, 985879, tzinfo=UTC),
            'last_observed_on': datetime(2024, 10, 2, 19, 22, 55, tzinfo=UTC),
        },
    }
