import pytest
from tenable.io import TenableIO
from carbonblack import CarbonBlackAPI


@pytest.fixture
def cba():
    return CarbonBlackAPI(
        url='https://nourl.carbonlack',
        api_id='test_api_id',
        api_secret='test_api_secret',
        org_key='test_org_key',
    )


@pytest.fixture
def tapi():
    return TenableIO(
        url='https://nourl.tvm',
        access_key='something',
        secret_key='something',
    )


@pytest.fixture
def asset_details():
    return {
        'activation_code': None,
        'activation_code_expiry_time': '2022-12-27T23:25:55.364Z',
        'ad_domain': None,
        'ad_group_id': 0,
        'ad_org_unit': None,
        'appliance_name': None,
        'appliance_uuid': None,
        'asset_group': [],
        'auto_scaling_group_name': None,
        'av_ave_version': None,
        'av_engine': None,
        'av_last_scan_time': None,
        'av_master': False,
        'av_pack_version': None,
        'av_product_version': None,
        'av_status': [],
        'av_update_servers': None,
        'av_vdf_version': None,
        'base_device': None,
        'cloud_provider_account_id': None,
        'cloud_provider_resource_id': None,
        'cloud_provider_tags': [],
        'cloud_provider_resource_group': None,
        'cloud_provider_scale_group': None,
        'cloud_provider_network': None,
        'cloud_provider_managed_identity': None,
        'cluster_name': None,
        'compliance_status': 'NOT_ASSESSED',
        'current_sensor_policy_name': 'Standar4ul5d1',
        'policy_override': True,
        'quarantined': True,
        'datacenter_name': None,
        'deployment_type': 'AWS',
        'deregistered_time': None,
        'device_meta_data_item_list': [
            {'key_name': 'OS_MAJOR_VERSION', 'key_value': 'Ubuntu 22', 'position': 0},
            {'key_name': 'SUBNET', 'key_value': '192.168.38.0', 'position': 0},
        ],
        'device_owner_id': 907361,
        'email': 'cayenne',
        'esx_host_name': None,
        'esx_host_uuid': None,
        'first_name': None,
        'golden_device': None,
        'golden_device_id': None,
        'groups': [],
        'host_based_firewall_reasons': [],
        'host_based_firewall_status': None,
        'id': 6697325,
        'infrastructure_provider': 'AWS',
        'last_contact_time': '2025-02-19T12:36:44.628Z',
        'last_device_policy_changed_time': '2025-02-06T03:16:45.766Z',
        'last_device_policy_requested_time': '2025-02-16T15:23:30.100Z',
        'last_external_ip_address': '52.53.135.128',
        'last_internal_ip_address': '192.168.38.251',
        'last_location': 'UNKNOWN',
        'last_name': None,
        'last_reported_time': '2025-02-19T12:21:42.946Z',
        'last_reset_time': None,
        'last_shutdown_time': None,
        'linux_kernel_version': None,
        'login_user_name': None,
        'mac_address': '062b5b412d99',
        'middle_name': None,
        'name': 'cayenne',
        'nsx_distributed_firewall_policy': None,
        'nsx_enabled': None,
        'organization_id': 1105,
        'organization_name': 'cb-internal-alliances.com',
        'os': 'LINUX',
        'os_version': 'Ubuntu 22.04.1 x64',
        'passive_mode': True,
        'policy_assignment_type': 'MANUAL',
        'policy_id': 80947,
        'policy_name': 'Standar4ul5d1',
        'registered_time': '2023-02-27T23:30:24.991Z',
        'scan_last_action_time': None,
        'scan_last_complete_time': None,
        'scan_status': None,
        'sensor_gateway_url': None,
        'sensor_gateway_uuid': None,
        'sensor_kit_type': 'UBUNTU',
        'sensor_out_of_date': True,
        'sensor_pending_update': False,
        'sensor_states': [
            'CSR_ACTION',
            'LIVE_RESPONSE_DISABLED',
            'LIVE_RESPONSE_NOT_RUNNING',
            'LIVE_RESPONSE_NOT_KILLED',
        ],
        'sensor_version': '2.14.0.1321525',
        'status': 'BYPASS',
        'target_priority': 'MEDIUM',
        'uninstall_code': 'IUH6FKL6',
        'vcenter_host_url': None,
        'vcenter_name': None,
        'vcenter_uuid': None,
        'vdi_base_device': None,
        'vdi_provider': 'NONE',
        'virtual_machine': True,
        'virtual_private_cloud_id': None,
        'virtualization_provider': 'OTHER',
        'vm_ip': None,
        'vm_name': None,
        'vm_uuid': None,
        'vulnerability_score': 5.5,
        'vulnerability_severity': 'MODERATE',
        'windows_platform': None,
        'last_policy_updated_time': '2025-02-16T15:23:17.461Z',
    }


@pytest.fixture
def finding_details():
    return {
        'os_product_id': '201_3340563',
        'category': 'OS',
        'os_info': {
            'os_type': 'AMAZON_LINUX',
            'os_name': 'Amazon Linux',
            'os_version': '2.0.0',
            'os_arch': 'x86_64',
        },
        'product_info': {
            'vendor': 'Amazon Linux',
            'product': 'glibc',
            'version': '2.26',
            'release': '58.amzn2',
            'arch': 'x86_64',
        },
        'vuln_info': {
            'cve_id': 'CVE-2009-5155',
            'cve_description': 'In the GNU C Library (aka glibc or libc6) before 2.28, parse_reg_exp in posix/regcomp.c misparses alternatives, which allows attackers to cause a denial of service (assertion failure and application exit) or trigger an incorrect result by attempting a regular-expression match.',
            'risk_meter_score': 0.9,
            'severity': 'LOW',
            'fixed_by': '2.26-62',
            'solution': None,
            'created_at': '2019-02-26T02:29:00Z',
            'nvd_link': 'https://nvd.nist.gov/vuln/detail/CVE-2009-5155',
            'cvss_access_complexity': 'LOW',
            'cvss_access_vector': 'NETWORK',
            'cvss_authentication': 'NONE',
            'cvss_availability_impact': 'HIGH',
            'cvss_confidentiality_impact': 'NONE',
            'cvss_integrity_impact': 'NONE',
            'easily_exploitable': False,
            'malware_exploitable': False,
            'active_internet_breach': False,
            'cvss_exploit_subscore': 10.0,
            'cvss_impact_subscore': 2.9,
            'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            'cvss_v3_exploit_subscore': 3.9,
            'cvss_v3_impact_subscore': 3.6,
            'cvss_v3_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            'cvss_score': 5.0,
            'cvss_v3_score': 7.5,
        },
        'device_count': 1,
        'affected_assets': ['ip-172-31-87-51.ec2.internal'],
        'rule_id': None,
        'dismissed': False,
        'dismiss_reason': None,
        'notes': None,
        'dismissed_on': None,
        'dismissed_by': None,
        'deployment_type': None,
    }


@pytest.fixture
def asset_details_response(asset_details):
    return {
        'num_found': 1,
        'results': [asset_details],
    }


@pytest.fixture
def finding_details_response(finding_details):
    return {
        'num_found': 1,
        'results': [finding_details],
    }
