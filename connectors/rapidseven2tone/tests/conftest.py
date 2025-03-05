import pytest
import json
from tenable.io import TenableIO

from rapidseven.api.session import RapidSevenAPI


@pytest.fixture
def rsapi():
    return RapidSevenAPI(
        url='https://10.50.12.188:3780',
        username='Something',
        password='Something',
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
        'addresses': [{'ip': '10.50.10.217', 'mac': '00:50:56:83:52:0e'}],
        'assessedForPolicies': False,
        'assessedForVulnerabilities': True,
        'history': [
            {
                'date': '2025-02-12T11:04:29.692Z',
                'scanId': 1,
                'type': 'SCAN',
                'version': 1,
            },
            {
                'date': '2025-02-17T06:45:17.366Z',
                'scanId': 2,
                'type': 'SCAN',
                'version': 2,
            },
        ],
        'id': 1,
        'ip': '10.50.10.217',
        'links': [
            {'href': 'https://10.50.12.188:3780/api/3/assets/1', 'rel': 'self'},
            {
                'href': 'https://10.50.12.188:3780/api/3/assets/1/software',
                'rel': 'Software',
            },
            {'href': 'https://10.50.12.188:3780/api/3/assets/1/files', 'rel': 'Files'},
            {'href': 'https://10.50.12.188:3780/api/3/assets/1/users', 'rel': 'Users'},
            {
                'href': 'https://10.50.12.188:3780/api/3/assets/1/user_groups',
                'rel': 'User Groups',
            },
            {
                'href': 'https://10.50.12.188:3780/api/3/assets/1/databases',
                'rel': 'Databases',
            },
            {
                'href': 'https://10.50.12.188:3780/api/3/assets/1/services',
                'rel': 'Services',
            },
            {'href': 'https://10.50.12.188:3780/api/3/assets/1/tags', 'rel': 'Tags'},
        ],
        'mac': '00:50:56:83:52:0e',
        'os': 'Ubuntu Linux',
        'osCertainty': '0.75',
        'osFingerprint': {
            'description': 'Ubuntu Linux',
            'family': 'Linux',
            'id': 1,
            'product': 'Linux',
            'systemName': 'Ubuntu Linux',
            'vendor': 'Ubuntu',
        },
        'rawRiskScore': 922.0,
        'riskScore': 922.0,
        'services': [
            {
                'configurations': [
                    {
                        'name': 'ssh.algorithms.compression',
                        'value': 'none,zlib@openssh.com',
                    },
                    {
                        'name': 'ssh.algorithms.encryption',
                        'value': 'aes128-ctr,aes192-ctr,aes256-ctr',
                    },
                    {
                        'name': 'ssh.algorithms.hostkey',
                        'value': 'rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519',
                    },
                    {
                        'name': 'ssh.algorithms.kex',
                        'value': 'sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com',
                    },
                    {
                        'name': 'ssh.algorithms.mac',
                        'value': 'hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512',
                    },
                    {
                        'name': 'ssh.banner',
                        'value': 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5',
                    },
                    {'name': 'ssh.hostkey.ecdsa.bits', 'value': '256'},
                    {
                        'name': 'ssh.hostkey.ecdsa.fingerprint',
                        'value': '9b:8d:9d:08:bc:71:14:a7:dc:93:1b:88:c2:bf:d9:3a',
                    },
                    {'name': 'ssh.hostkey.ed25519.bits', 'value': '256'},
                    {
                        'name': 'ssh.hostkey.ed25519.fingerprint',
                        'value': '31:4f:b6:92:44:d2:1a:94:14:64:dc:d9:ed:9d:44:3c',
                    },
                    {'name': 'ssh.hostkey.type', 'value': 'ECDSA,ED25519'},
                    {'name': 'ssh.protocol.version', 'value': '2.0'},
                ],
                'family': 'OpenSSH',
                'links': [
                    {
                        'href': 'https://10.50.12.188:3780/api/3/assets/1/services/tcp/22',
                        'rel': 'self',
                    },
                    {
                        'href': 'https://10.50.12.188:3780/api/3/assets/1/services/tcp/22/configurations',
                        'rel': 'Configurations',
                    },
                    {
                        'href': 'https://10.50.12.188:3780/api/3/assets/1/services/tcp/22/databases',
                        'rel': 'Databases',
                    },
                    {
                        'href': 'https://10.50.12.188:3780/api/3/assets/1/services/tcp/22/users',
                        'rel': 'Users',
                    },
                    {
                        'href': 'https://10.50.12.188:3780/api/3/assets/1/services/tcp/22/user_groups',
                        'rel': 'User Groups',
                    },
                    {
                        'href': 'https://10.50.12.188:3780/api/3/assets/1/services/tcp/22/web_applications',
                        'rel': 'Web Applications',
                    },
                ],
                'name': 'SSH',
                'port': 22,
                'product': 'OpenSSH',
                'protocol': 'tcp',
                'vendor': 'OpenBSD',
                'version': '9.6p1',
            }
        ],
        'vulnerabilities': {
            'critical': 1,
            'exploits': 0,
            'malwareKits': 0,
            'moderate': 0,
            'severe': 1,
            'total': 2,
        },
    }


@pytest.fixture
def asset_page_one(asset):
    return {
        'resources': [asset],
        'page': {'number': 0, 'size': 10, 'totalResources': 1, 'totalPages': 1},
        'links': [
            {
                'href': 'https://10.50.12.188:3780/api/3/assets?page=0&size=10&sort=id,asc',
                'rel': 'self',
            }
        ],
    }


@pytest.fixture
def asset_id():
    return 1


@pytest.fixture
def linux_os():
    return 'linux 6.3'


@pytest.fixture
def windows_os():
    return 'windows 2012'


@pytest.fixture
def unknown_os():
    return 'general os'


@pytest.fixture
def asset_vuln():
    return {
        'id': 'openbsd-openssh-cve-2024-6387',
        'instances': 1,
        'links': [
            {
                'href': 'https://10.50.12.188:3780/api/3/assets/1/vulnerabilities/openbsd-openssh-cve-2024-6387',
                'rel': 'self',
            },
            {
                'id': 'openbsd-openssh-cve-2024-6387',
                'href': 'https://10.50.12.188:3780/api/3/vulnerabilities/openbsd-openssh-cve-2024-6387',
                'rel': 'Vulnerability',
            },
            {
                'id': 'openbsd-openssh-cve-2024-6387',
                'href': 'https://10.50.12.188:3780/api/3/assets/1/vulnerabilities/openbsd-openssh-cve-2024-6387/validations',
                'rel': 'Vulnerability Validations',
            },
            {
                'id': 'openbsd-openssh-cve-2024-6387',
                'href': 'https://10.50.12.188:3780/api/3/assets/1/vulnerabilities/openbsd-openssh-cve-2024-6387/solution',
                'rel': 'Vulnerability Solutions',
            },
        ],
        'results': [
            {
                'port': 22,
                'proof': '<p><ul><li>Running SSH service</li><li>Product OpenSSH exists -- OpenBSD OpenSSH 9.6p1</li><li>Vulnerable version of product OpenSSH found -- OpenBSD OpenSSH 9.6p1</li></ul><p>Vulnerable version of OpenSSH detected on Ubuntu Linux</p></p>',
                'protocol': 'tcp',
                'since': '2025-02-12T11:04:29.692Z',
                'status': 'vulnerable-version',
            }
        ],
        'since': '2025-02-12T11:04:29.692Z',
        'status': 'vulnerable',
    }


@pytest.fixture
def vuln_id():
    return 'openbsd-openssh-cve-2024-6387'


@pytest.fixture
def vuln_info():
    return {
        'added': '2024-07-02',
        'categories': ['OpenSSH', 'SSH'],
        'cves': ['CVE-2024-6387'],
        'cvss': {
            'links': [
                {
                    'href': 'https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=(AV:N/AC:H/Au:N/C:C/I:C/A:C)',
                    'rel': 'CVSS v2 Calculator',
                },
                {
                    'href': 'https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
                    'rel': 'CVSS v3 Calculator',
                },
            ],
            'v2': {
                'accessComplexity': 'H',
                'accessVector': 'N',
                'authentication': 'N',
                'availabilityImpact': 'C',
                'confidentialityImpact': 'C',
                'exploitScore': 4.928,
                'impactScore': 10.0008,
                'integrityImpact': 'C',
                'score': 7.6,
                'vector': 'AV:N/AC:H/Au:N/C:C/I:C/A:C',
            },
            'v3': {
                'attackComplexity': 'H',
                'attackVector': 'N',
                'availabilityImpact': 'H',
                'confidentialityImpact': 'H',
                'exploitScore': 2.2212,
                'impactScore': 5.8731,
                'integrityImpact': 'H',
                'privilegeRequired': 'N',
                'scope': 'U',
                'score': 8.1,
                'userInteraction': 'N',
                'vector': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
            },
        },
        'denialOfService': False,
        'description': {
            'html': '<p>A security regression (CVE-2006-5051) was discovered in OpenSSH&#39;s server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.</p>',
            'text': "A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.",
        },
        'exploits': 0,
        'id': 'openbsd-openssh-cve-2024-6387',
        'links': [
            {
                'href': 'https://10.50.12.188:3780/api/3/vulnerabilities/openbsd-openssh-cve-2024-6387',
                'rel': 'self',
            },
            {
                'href': 'https://10.50.12.188:3780/api/3/vulnerabilities/openbsd-openssh-cve-2024-6387/checks',
                'rel': 'Vulnerability Checks',
            },
            {
                'href': 'https://10.50.12.188:3780/api/3/vulnerabilities/openbsd-openssh-cve-2024-6387/references',
                'rel': 'Vulnerability References',
            },
            {
                'href': 'https://10.50.12.188:3780/api/3/vulnerabilities/openbsd-openssh-cve-2024-6387/malware_kits',
                'rel': 'Vulnerability Malware Kits',
            },
            {
                'href': 'https://10.50.12.188:3780/api/3/vulnerabilities/openbsd-openssh-cve-2024-6387/exploits',
                'rel': 'Vulnerability Exploits',
            },
            {
                'href': 'https://10.50.12.188:3780/api/3/vulnerabilities/openbsd-openssh-cve-2024-6387/solutions',
                'rel': 'Vulnerability Solutions',
            },
        ],
        'malwareKits': 0,
        'modified': '2024-09-05',
        'pci': {
            'adjustedCVSSScore': 7,
            'adjustedSeverityScore': 5,
            'fail': True,
            'status': 'Fail',
        },
        'published': '2024-07-01',
        'riskScore': 654.0,
        'severity': 'Critical',
        'severityScore': 8,
        'title': 'OpenSSH Vulnerability: CVE-2024-6387',
    }


@pytest.fixture
def vuln_page_one(asset_vuln):
    return {
        'resources': [asset_vuln],
        'page': {'number': 0, 'size': 500, 'totalResources': 1, 'totalPages': 1},
        'links': [
            {
                'href': 'https://10.50.12.188:3780/api/3/assets/1/vulnerabilities?page=0&size=500&sort=id,asc',
                'rel': 'self',
            }
        ],
    }


@pytest.fixture
def kbs_page(vuln_info):
    return {
        'resources': [vuln_info],
        'page': {'number': 0, 'size': 500, 'totalResources': 1, 'totalPages': 1},
        'links': [
            {
                'href': 'https://10.50.12.188:3780/api/3/assets/1/vulnerabilities?page=0&size=500&sort=id,asc',
                'rel': 'self',
            }
        ],
    }
