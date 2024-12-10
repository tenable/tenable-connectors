
import pytest
from tenable.io.sync.models.device_asset import DeviceAsset

from crowdstrike.transform import Transformer


@pytest.fixture
def transformer(csapi, tapi):
    return Transformer(crwd=csapi, tvm=tapi)


def test_transform_asset(transformer, asset_details):
    tnx_asset = {
        'device': {
            'networking': {
                'ip_addresses_v4': [{'address': '8.8.8.8'}, {'address': '172.1.1.2'}],
                'mac_addresses': ['6e:61:0e:cb:da:68'],
            },
        },
        'discovery': {
            'first_observed_at': '2024-12-08T00:05:01Z',
            'last_observed_on': '2024-12-08T00:05:01Z',
        },
        'labels': [
            'SensorGroupingTags/CloudSecurity',
            'SensorGroupingTags/DevUse2Dep3Eks1Backend',
        ],
        'id': '11111111111',
        'name': 'ip-10-1-1-2.us-east-2.compute.internal',
        'object_type': 'device-asset',
        'asset_class': 'DEVICE',
    }

    asset = transformer.transform_asset(asset_details)
    assert DeviceAsset(**asset).model_dump(mode='json', exclude_none=True) == tnx_asset
