import pytest
from tenable.io import TenableIO
from crowdstrike import CrowdStrikeAPI
import responses


@pytest.fixture
def token_page():
    return {
        'access_token': 'test_token',
        'expires_in': 1788,
        'token_type': 'bearer'
    }

@pytest.fixture()
def token_response(token_page):
    with responses.RequestsMock() as rsps:
        # Add your global responses here
        rsps.add(
            method=responses.POST,
            url='https://nourl.crowdstrike/oauth2/token',
            #match=[
            #    json_params_matcher({
            #        'resource': 'https://api.securitycenter.windows.com',
            #        'client_id': app_id,
            #        'client_secret': app_secret,
            #        'grant_type': 'client_credentials',
            #    })
            #    
            #],
            json=token_page,
        )
        yield rsps

@pytest.fixture
def csapi(token_response):
    return CrowdStrikeAPI(
        url='https://nourl.crowdstrike',
        client_id='test_client_id',
        client_secret='test_client_secret',
        member_cid='test_member_cid',
    )

@pytest.fixture
def tapi():
    return TenableIO(
        url='https://nourl.tvm',
        access_key='something',
        secret_key='something',
    )

@pytest.fixture
def asset_id():
    return '11111111111'
        

@pytest.fixture
def asset_id_page(asset_id):
    return {
        'meta': {
            'query_time': 0.139107412, 
            'pagination': {
                'total': 2, 
                'expires_at': 1733701742592134923
            }, 
            'powered_by': 'device-api', 
            'trace_id': 'example_trace_id'
        }, 
        'resources': [],
        'errors': []
    }

@pytest.fixture
def asset_id_page_one(asset_id):
    return {
        'meta': {
            'query_time': 0.139107412, 
            'pagination': {
                'total': 2, 
                'offset': 'example_offset', 
                'expires_at': 1733701742592134923
            }, 
            'powered_by': 'device-api', 
            'trace_id': 'example_trace_id'
        }, 
        'resources': [asset_id],
        'errors': []
    }

@pytest.fixture
def asset_details():
    return {
        'agent_load_flags': '0',
        'agent_local_time': '2024-12-08T00:04:53.812Z',
        'agent_version': '7.14.16703.0',
        'base_image_version': '9.3-15',
        'bios_manufacturer': 'Amazon EC2',
        'bios_version': '1.0',
        'chassis_type': '1',
        'chassis_type_desc': 'Other',
        'cid': 'example_customer_id',
        'config_id_base': '65994763',
        'config_id_build': '16703',
        'config_id_platform': '128',
        'connection_ip': '10.1.1.2',
        'connection_mac_address': '02-3b-d8-cb-92-89',
        'cpu_signature': '4294967295',
        'cpu_vendor': '3',
        'default_gateway_ip': '10.1.1.1',
        'deployment_type': 'DaemonSet',
        'device_id': '11111111111',
        'device_policies': {
            'content-update': {
                'applied': True,
                'applied_date': '2024-12-08T00:06:08.839346335Z',
                'assigned_date': '2024-12-08T00:06:08.839346335Z',
                'policy_id': '354b88b144254c329dccda320fa39cc8',
                'policy_type': 'content-update',
                'settings_hash': '15149298583092720469'
            },
            'global_config': {
                'applied': False,
                'applied_date': None,
                'assigned_date': '2024-12-08T00:06:08.837964971Z',
                'policy_id': '29e1efd45cab4fc28e11e74260e1cd3c',
                'policy_type': 'globalconfig',
                'settings_hash': '12ecd2db'
            },
            'host-retention': {
                'applied': False,
                'applied_date': None,
                'assigned_date': '2024-12-08T00:06:08.857961164Z',
                'policy_id': '0e31ef23c8d141c6b7950118aac92153',
                'policy_type': 'host-retention',
                'settings_hash': 'fce339fc6cbb4dae36929fe363a81368f4a7e3f2c3a3d62ff7e3ef202ee48df5'
            },
            'prevention': {
                'applied': False,
                'applied_date': None,
                'assigned_date': '2024-12-08T00:06:08.833811644Z',
                'policy_id': 'ae00fe9bd81c4507a1e6598bc20e83af',
                'policy_type': 'prevention',
                'rule_groups': [],
                'settings_hash': 'b798de53'
            },
            'remote_response': {
                'applied': False,
                'applied_date': None,
                'assigned_date': '2024-12-08T00:06:08.852982767Z',
                'policy_id': '54d313eb5d4a483a96ca3ae9baa28ee0',
                'policy_type': 'remote-response',
                'settings_hash': '188b205c'
            },
            'sensor_update': {
                'applied': False,
                'applied_date': None,
                'assigned_date': '2024-12-08T00:06:08.84717931Z',
                'policy_id': 'e865ead304354114b98d8eec6d764286',
                'policy_type': 'sensor-update',
                'settings_hash': 'tagged|12;0',
                'uninstall_protection': 'UNKNOWN'
            }
        },
        'external_ip': '8.8.8.8',
        'filesystem_containment_status': 'normal',
        'first_seen': '2024-12-08T00:05:01Z',
        'group_hash': 'ead77444393c2a351deebf62b361eef72de1a99022e13a652e6c317242c98cd1',
        'groups': ['2fd37c5cf03b48d69d2ce0a09d400dbd'],
        'hostname': 'ip-10-1-1-2.us-east-2.compute.internal',
        'instance_id': 'i-example4f7a67bed',
        'kernel_version': '6.1.115-126.197.amzn2023.aarch64',
        'last_seen': '2024-12-08T00:05:01Z',
        'linux_sensor_mode': 'User Mode',
        'local_ip': '172.1.1.2',
        'mac_address': '6e-61-0e-cb-da-68',
        'major_version': '6',
        'meta': {'version': '5', 'version_string': '5:340077890'},
        'minor_version': '1',
        'modified_timestamp': '2024-12-08T00:06:09Z',
        'os_version': 'Amazon Linux 2023',
        'platform_id': '3',
        'platform_name': 'Linux',
        'policies': [{
            'applied': False,
            'applied_date': None,
            'assigned_date': '2024-12-08T00:06:08.833811644Z',
            'policy_id': 'ae00fe9bd81c4507a1e6598bc20e83af',
            'policy_type': 'prevention',
            'rule_groups': [],
            'settings_hash': 'b798de53'
        }],
        'product_type_desc': 'Server',
        'reduced_functionality_mode': 'no',
        'serial_number': 'ec2d9982-1ab8-cfb5-552b-34c568a57fc9',
        'service_provider': 'AWS_EC2_V2',
        'service_provider_account_id': '020311179611',
        'status': 'normal',
        'system_manufacturer': 'Amazon EC2',
        'system_product_name': 'm8g.2xlarge',
        'tags': [
            'SensorGroupingTags/CloudSecurity',
            'SensorGroupingTags/DevUse2Dep3Eks1Backend'
        ],
        'zone_group': 'us-east-2a'
    }

@pytest.fixture
def asset_details_page(asset_details):
    return {
        'meta': {
            'query_time': 0.139107412, 
            'pagination': {
                'total': 2, 
                'expires_at': 1733701742592134923
            }, 
            'powered_by': 'device-api', 
            'trace_id': 'example_trace_id'
        }, 
        'resources': [asset_details],
        'errors': []
    }
def asset_details_page_one(asset_details):
    return {
        'meta': {
            'query_time': 0.139107412, 
            'pagination': {
                'total': 2, 
                'offset': 'example_offset', 
                'expires_at': 1733701742592134923
            }, 
            'powered_by': 'device-api', 
            'trace_id': 'example_trace_id'
        }, 
        'resources': [asset_details],
        'errors': []
    }
    