import pytest
from tenable.io.sync.models.device_asset import DeviceAsset

from crowdstrike.transform import Transformer


@pytest.fixture
def transformer(csapi, tapi):
    return Transformer(crwd=csapi, tvm=tapi)


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
                'network_group_id': '3d855da0-4efa-463b-9095-08317dc46035',
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
    assert tnx_asset['device'] == a['device']
    assert tnx_asset['discovery'] == a['discovery']
    assert len(tnx_asset['labels']) == len(a['labels'])
    assert tnx_asset['id'] == a['id']
    assert tnx_asset['name'] == a['name']
