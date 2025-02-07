import pytest
from tenable.io import TenableIO

from sentinelone import SentinelOneAPI


@pytest.fixture
def s1api():
    return SentinelOneAPI(url='https://nourl.s1', api_token='test_api_token')


@pytest.fixture
def tapi():
    return TenableIO(
        url='https://nourl.tvm',
        access_key='something',
        secret_key='something',
    )


@pytest.fixture
def agent():
    return {
        'accountId': '2010956593562169647',
        'accountName': 'Tenable',
        'activeDirectory': {
            'computerDistinguishedName': None,
            'computerMemberOf': [],
            'lastUserDistinguishedName': None,
            'lastUserMemberOf': [],
            'userPrincipalName': None,
        },
        'activeThreats': 0,
        'agentVersion': '24.1.2.6',
        'allowRemoteShell': True,
        'appsVulnerabilityStatus': 'not_applicable',
        'cloudProviders': {
            'AWS': {
                'awsRole': None,
                'awsSecurityGroups': ['launch-wizard-5'],
                'awsSubnetIds': ['subnet-08185681ab9f6958c'],
                'cloudAccount': '193468595165',
                'cloudImage': 'ami-0075013580f6322a1',
                'cloudInstanceId': 'i-03e182c654e3e0131',
                'cloudInstanceSize': 't2.medium',
                'cloudLocation': 'us-west-2',
                'cloudNetwork': 'vpc-01c8106aefd58d6ee',
                'cloudTags': [
                    'Endpoint does not have sufficient permissions to fetch tags'
                ],
            }
        },
        'computerName': 'ip-172-31-4-242',
        'consoleMigrationStatus': 'N/A',
        'containerizedWorkloadCounts': None,
        'coreCount': 2,
        'cpuCount': 1,
        'cpuId': 'Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz',
        'createdAt': '2024-08-07T17:57:08.475617Z',
        'detectionState': None,
        'domain': 'us-west-2.compute.internal',
        'encryptedApplications': False,
        'externalId': '',
        'externalIp': '35.89.96.104',
        'firewallEnabled': True,
        'firstFullModeTime': None,
        'fullDiskScanLastUpdatedAt': '2024-08-07T18:13:09.081514Z',
        'groupId': '2010956594753351995',
        'groupIp': '35.89.96.x',
        'groupName': 'Default Group',
        'hasContainerizedWorkload': False,
        'id': '2011794797031672400',
        'inRemoteShellSession': False,
        'infected': False,
        'installerType': '.deb',
        'isActive': True,
        'isAdConnector': False,
        'isDecommissioned': False,
        'isPendingUninstall': False,
        'isUninstalled': False,
        'isUpToDate': True,
        'lastActiveDate': '2024-12-06T05:52:59.983806Z',
        'lastIpToMgmt': '172.31.4.242',
        'lastLoggedInUserName': '',
        'lastSuccessfulScanDate': '2024-08-07T18:13:09.081514Z',
        'licenseKey': '',
        'locationEnabled': False,
        'locationType': 'not_supported',
        'locations': None,
        'machineSid': None,
        'machineType': 'server',
        'missingPermissions': [],
        'mitigationMode': 'protect',
        'mitigationModeSuspicious': 'detect',
        'modelName': 'Xen HVM domU',
        'networkInterfaces': [
            {
                'gatewayIp': '172.31.0.1',
                'gatewayMacAddress': '0a:ca:40:31:81:d5',
                'id': '2011794797040061009',
                'inet': ['172.31.4.242'],
                'inet6': ['fe80::887:7aff:fe4f:b40b'],
                'name': 'eth0',
                'physical': '0A:87:7A:4F:B4:0B',
            }
        ],
        'networkQuarantineEnabled': False,
        'networkStatus': 'connected',
        'operationalState': 'na',
        'operationalStateExpiration': None,
        'osArch': '64 bit',
        'osName': 'Linux',
        'osRevision': 'Ubuntu 22.04.4 LTS 6.5.0-1022-aws',
        'osStartTime': '2024-08-07T17:44:38Z',
        'osType': 'linux',
        'osUsername': 'root',
        'proxyStates': None,
        'rangerStatus': 'Disabled',
        'rangerVersion': None,
        'registeredAt': '2024-08-07T17:57:08.470993Z',
        'remoteProfilingState': 'disabled',
        'remoteProfilingStateExpiration': None,
        'scanAbortedAt': None,
        'scanFinishedAt': '2024-08-07T18:13:09.081514Z',
        'scanStartedAt': '2024-08-07T17:58:01.554887Z',
        'scanStatus': 'finished',
        'serialNumber': None,
        'showAlertIcon': False,
        'siteId': '2010956594736574778',
        'siteName': 'Default site',
        'storageName': None,
        'storageType': None,
        'tags': {
            'sentinelone': [
                {
                    'assignedAt': '2024-10-22T16:01:01.340629Z',
                    'assignedBy': 'Steven Mcgrath',
                    'assignedById': '2066199083134455910',
                    'id': '2066818480984269794',
                    'key': 'test',
                    'value': 'value',
                }
            ]
        },
        'threatRebootRequired': False,
        'totalMemory': 3904,
        'updatedAt': '2024-12-06T03:43:42.885065Z',
        'userActionsNeeded': [],
        'uuid': 'e9ef4ceb-0e54-dd89-70e6-e0f8f827a098',
    }


@pytest.fixture
def agent_page(agent):
    # No next page data
    ret = {
        'data': [agent],
        'pagination': {
            'totalItems': 1,
            'nextCursor': None,
        },
    }
    # return json.dumps(ret).encode('utf-8')
    return ret


@pytest.fixture
def agent_page_one(agent):
    ret = {
        'data': [agent],
        'pagination': {
            'nextCursor': 'example-cursor',
            'totalItems': 1,
        },
    }
    return ret


@pytest.fixture
def app():
    return {
        'applicationId': '1807951750242764456',
        'cveCount': 1,
        'daysDetected': 114,
        'detectionDate': '2024-08-14T21:37:26.985879Z',
        'endpointCount': 1,
        'estimate': False,
        'highestNvdBaseScore': '3.30',
        'highestSeverity': 'LOW',
        'name': 'accountsservice 0.6.45-1ubuntu1.3',
        'vendor': 'Ubuntu Developers &lt;ubuntu-devel-discuss@lists.ubuntu.com&gt;',
    }


@pytest.fixture
def app_page(app):
    # No next page data
    ret = {
        'data': [app],
        'pagination': {
            'totalItems': 1,
            'nextCursor': None,
        },
    }
    return ret


@pytest.fixture
def app_page_one(app):
    ret = {
        'data': [app],
        'pagination': {
            'nextCursor': 'example-cursor',
            'totalItems': 1,
        },
    }
    return ret


@pytest.fixture
def app_id():
    return '1807951750242764456'


@pytest.fixture
def cve():
    return {
        'cveId': 'CVE-2012-6655',
        'cvssVersion': '3.1',
        'description': 'A vulnerability was found in AccountService 0.6.37.',
        'fpFnMarks': None,
        'mitreUrl': 'https://www.cve.org/CVERecord?id=CVE-2012-6655',
        'nvdBaseScore': '3.30',
        'nvdUrl': 'https://nvd.nist.gov/vuln/detail/CVE-2012-6655',
        'publishedDate': '2019-11-27T18:15:00Z',
        'severity': 'LOW',
    }


@pytest.fixture
def cve_page(cve):
    # No next page data
    ret = {
        'data': [cve],
        'pagination': {
            'totalItems': 1,
            'nextCursor': None,
        },
    }
    return ret


@pytest.fixture
def cve_page_one(cve):
    ret = {
        'data': [cve],
        'pagination': {
            'nextCursor': 'example-cursor',
            'totalItems': 1,
        },
    }
    return ret


@pytest.fixture
def endpoint():
    return {
        'accountName': 'Tenable',
        'applicationDaysDetected': 114,
        'applicationDetectionDate': '2024-08-14T21:37:26.985879Z',
        'applicationVersion': '0.6.45-1ubuntu1.3',
        'domain': 'unknown',
        'endpointId': '2011957903825504800',
        'endpointName': 'nkeuning-sentinelone',
        'endpointType': 'server',
        'endpointUuid': 'e99b8224-ce51-d467-a643-53b2cf13479f',
        'externalTicketSystem': {'available': False, 'type': None},
        'groupName': 'Default Group',
        'lastScanDate': '2024-10-02T19:22:55Z',
        'lastScanResult': 'Succeeded',
        'osType': 'linux',
        'osVersion': 'Linux Ubuntu 18.04.3 LTS 5.4.0-150-generic',
        'siteName': 'Default site',
        'ticket': None,
    }


@pytest.fixture
def endpoint_page(endpoint):
    # No next page data
    ret = {
        'data': [endpoint],
        'pagination': {
            'totalItems': 1,
            'nextCursor': None,
        },
    }
    return ret


@pytest.fixture
def endpoint_page_one(endpoint):
    ret = {
        'data': [endpoint],
        'pagination': {
            'nextCursor': 'example-cursor',
            'totalItems': 1,
        },
    }
    return ret
