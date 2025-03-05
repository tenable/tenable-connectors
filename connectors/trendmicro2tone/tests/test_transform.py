import pytest
from tenable.io.sync.models.device_asset import DeviceAsset

from trendmicro.transform import Transformer


@pytest.fixture
def transformer(tmapi, tapi):
    return Transformer(tvm=tapi, trendmicro=tmapi)


def test_transformer_get_os_type(transformer):
    assert transformer.get_os_type('Windows XP') == 'WINDOWS'
    assert transformer.get_os_type('RedHat Enterprise Linux 8.0') == 'LINUX'
    assert transformer.get_os_type('Apple MacOS Yosemite') == 'MAC_OS'


def test_asset_transformer(transformer, asset):
    asset = transformer.transform_asset(asset)
    resp = DeviceAsset(**asset).model_dump(mode='json', exclude_none=True)
    assert resp['id'] == '66817e50-b0dd-476f-90c5-1a185ec62a4b'
    assert resp['name'] == 'ASSETTAG-EID'
    assert resp['device']['hardware']['serial_number'] == 'R90WVBB0'
    assert resp['device']['system_type'] == 'desktop'
    assert {'address': '172.20.0.213'} in resp['device']['networking'][
        'ip_addresses_v4'
    ]
    assert {'address': '5be8:dde9:7f0b:d5a7:bd01:b3be:9c69:573b'} in resp['device'][
        'networking'
    ]['ip_addresses_v6']
    assert resp['device']['operating_system']['type'] == 'WINDOWS'
    assert resp['device']['operating_system']['product']['product_name'] == 'windows 11'
    assert (
        resp['device']['operating_system']['product']['version'] == '10.0 (build 22631)'
    )


def test_categorized_ips_invalid_ip(transformer, asset):
    asset['ipAddresses'] = ['invalid_ip']
    with pytest.raises(
        ValueError, match=f'{asset["ipAddresses"][0]} is not a valid IP Address'
    ):
        transformer.transform_asset(asset)
