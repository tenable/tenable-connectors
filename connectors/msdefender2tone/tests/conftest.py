import pytest
import responses
from tenable.io import TenableIO

from msdefender.api.session import MSDefenderAPI


@pytest.fixture
def tenant_id():
    return 'something'


@pytest.fixture
def app_id():
    return 'something'


@pytest.fixture
def app_secret():
    return 'something'


@pytest.fixture
def auth_token():
    return 'test_token'


@pytest.fixture
def auth_page(auth_token):
    return {'access_token': auth_token}


@pytest.fixture()
def token_response(tenant_id, app_id, app_secret, auth_page):
    with responses.RequestsMock() as rsps:
        # Add your global responses here
        rsps.add(
            method=responses.POST,
            url=f'https://nourl.msdefender/{tenant_id}/oauth2/token',
            # match=[
            #    json_params_matcher({
            #        'resource': 'https://api.securitycenter.windows.com',
            #        'client_id': app_id,
            #        'client_secret': app_secret,
            #        'grant_type': 'client_credentials',
            #    })
            #
            # ],
            json=auth_page,
        )
        yield rsps


@pytest.fixture
def msdapi(tenant_id, app_id, app_secret, token_response):
    return MSDefenderAPI(
        tenant_id=tenant_id,
        app_id=app_id,
        app_secret=app_secret,
        url='https://nourl.msdefender',
        _base_token_url='https://nourl.msdefender',
    )


@pytest.fixture
def tapi():
    return TenableIO(
        url='https://nourl.tvm',
        access_key='something',
        secret_key='something',
    )


@pytest.fixture
def asset():
    return {
        'aadDeviceId': None,
        'agentVersion': '30.124052.2.0',
        'computerDnsName': 'tar-oracle-9.labnet.local',
        'defenderAvStatus': 'NotSupported',
        'deviceValue': 'Normal',
        'exclusionReason': None,
        'exposureLevel': 'Medium',
        'firstSeen': '2024-07-25T12:59:25.383557Z',
        'healthStatus': 'Active',
        'id': '080eaae77b6953abe2dbb471cc749baba40b040f',
        'ipAddresses': [
            {
                'ipAddress': '192.168.1.42',
                'macAddress': '005056ABD64C',
                'operationalStatus': 'Up',
                'type': 'Other',
            },
            {
                'ipAddress': 'fe80::250:56ff:feab:d64c',
                'macAddress': '005056ABD64C',
                'operationalStatus': 'Up',
                'type': 'Other',
            },
            {
                'ipAddress': '127.0.0.1',
                'macAddress': '000000000000',
                'operationalStatus': 'Up',
                'type': 'Other',
            },
            {
                'ipAddress': '::1',
                'macAddress': '000000000000',
                'operationalStatus': 'Up',
                'type': 'Other',
            },
        ],
        'isAadJoined': False,
        'isExcluded': False,
        'isPotentialDuplication': False,
        'lastExternalIpAddress': '100.16.206.202',
        'lastIpAddress': '192.168.1.42',
        'lastSeen': '2024-12-07T23:33:15.8729949Z',
        'machineTags': [''],
        'managedBy': 'Unknown',
        'managedByStatus': 'Unknown',
        'mergedIntoMachineId': None,
        'onboardingStatus': 'Onboarded',
        'osArchitecture': '64-bit',
        'osBuild': None,
        'osPlatform': 'OracleLinux',
        'osProcessor': 'x64',
        'osVersion': None,
        'rbacGroupId': 73,
        'rbacGroupName': 'UnassignedGroup',
        'riskScore': 'None',
        'version': '9.0',
        'vmMetadata': None,
    }


@pytest.fixture
def asset_page_one(asset):
    ret = {
        'value': [asset],
    }
    return ret


@pytest.fixture
def asset_page(asset):
    ret = {
        'value': [],
    }
    return ret


@pytest.fixture
def definition():
    return {
        'cveSupportability': 'Supported',
        'cvssV3': 9.4,
        'cvssVector': '',
        'description': 'Summary: The vulnerability allows remote attackers to execute '
        'arbitrary code or cause a denial of service (DoS) condition '
        'on the affected system. The issue is due to improper input '
        'validation of user-supplied data, which can be exploited to '
        'execute arbitrary commands or crash the system. Attackers can '
        'exploit this vulnerability by sending specially crafted '
        'requests to the targeted system. Impact: Successful '
        'exploitation of this vulnerability could result in remote '
        'code execution, allowing attackers to gain unauthorized '
        'access to the affected system, execute arbitrary commands, '
        'and potentially take control of the system. Additionally, a '
        'successful attack could cause a denial of service condition, '
        'rendering the system unavailable to legitimate users. '
        'Remediation: Apply the latest patches and updates provided by '
        'the respective vendors. [Generated by AI]',
        'epss': None,
        'exploitInKit': False,
        'exploitTypes': [],
        'exploitUris': [],
        'exploitVerified': False,
        'exposedMachines': 0,
        'firstDetected': None,
        'id': 'TVM-2020-0002',
        'name': 'TVM-2020-0002',
        'publicExploit': False,
        'publishedOn': '2020-12-16T00:00:00Z',
        'severity': 'Critical',
        'tags': [],
        'updatedOn': '2020-12-16T00:00:00Z',
    }


@pytest.fixture
def definition_page_one(definition):
    ret = {
        'value': [definition],
    }
    return ret


@pytest.fixture
def definition_page(definition):
    ret = {
        'value': [],
    }
    return ret


@pytest.fixture
def vuln():
    return {
        'cveId': 'CVE-2024-9936',
        'fixingKbId': None,
        'id': '24f7e1b0edb56c2952eff253eca1428586057dbf-_-CVE-2024-9936-_-mozilla-_-firefox-_-83.0.0.0-_-',
        'machineId': '24f7e1b0edb56c2952eff253eca1428586057dbf',
        'productName': 'firefox',
        'productVendor': 'mozilla',
        'productVersion': '83.0.0.0',
        'severity': 'Medium',
    }


@pytest.fixture
def vuln_page_one(definition):
    ret = {
        'value': [definition],
    }
    return ret


@pytest.fixture
def vuln_page(definition):
    ret = {
        'value': [],
    }
    return ret
