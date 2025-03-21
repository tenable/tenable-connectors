from unittest.mock import MagicMock

import pytest
from tenable.io import TenableIO

from trendmicro.api.session import TrendMicroAPI


@pytest.fixture
def tmapi():
    api = MagicMock(spec=TrendMicroAPI(url='https://nourl.v1', token='test_token'))
    return api


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
        'endpointName': 'ASSETTAG-EID',
        'agentGuid': '66817e50-b0dd-476f-90c5-1a185ec62a4b',
        'type': 'desktop',
        'displayName': 'ASSETTAG-EID',
        'osName': 'Windows 11',
        'osVersion': '10.0 (Build 22631)',
        'osArchitecture': 'x86_64',
        'osPlatform': 'windows',
        'lastUsedIp': '172.20.0.213',
        'cpuArchitecture': '64-bit',
        'lastLoggedOnUser': 'ASSETTAG-EID\\Crest',
        'isolationStatus': 'off',
        'ipAddresses': ['172.20.0.213', '5be8:dde9:7f0b:d5a7:bd01:b3be:9c69:573b'],
        'serialNumber': 'R90WVBB0',
        'serviceGatewayOrProxy': 'Direct connect',
        'versionControlPolicy': 'Default',
        'agentUpdateStatus': 'onSchedule',
        'agentUpdatePolicy': 'n',
        'creditAllocatedLicenses': ['Advanced Endpoint Security'],
        'eppAgent': {
            'endpointGroup': 'Workgroup',
            'protectionManager': 'test',
            'policyName': '',
            'status': 'off',
            'lastConnectedDateTime': '2025-02-14T09:19:11',
            'version': '14.0.14262',
            'lastScannedDateTime': '',
            'componentVersion': 'outdatedVersion',
            'componentUpdatePolicy': 'n',
            'componentUpdateStatus': 'onSchedule',
            'installedComponentIds': [
                '1082130432',
                '536870944',
                '1208221953',
                '1208222100',
                '1208221798',
                '1208222211',
                '1208222245',
                '1208222096',
                '1090519040',
                '1208222021',
                '1073741840',
                '1208222099',
                '1073741856',
                '1208221808',
                '1208221779',
                '1208221988',
                '536870976',
                '1208221844',
                '1208222307',
                '1208090624',
                '1208221826',
            ],
            'patterns': [
                {'id': '1082130432', 'name': 'Digital Signature Pattern'},
                {'id': '536870944', 'name': 'IntelliTrap Exception Pattern'},
                {
                    'id': '1208221953',
                    'name': 'Early Launch Anti-Malware Pattern (64-bit)',
                },
                {'id': '1208222100', 'name': 'Script Analyzer Unified Pattern'},
                {'id': '1208221798', 'name': 'Memory Inspection Pattern'},
                {'id': '1208222211', 'name': 'Program Inspection Monitoring Pattern'},
                {'id': '1208222245', 'name': 'Threat Tracing Pattern (64-bit)'},
                {'id': '1208222096', 'name': 'Contextual Intelligence Pattern'},
                {
                    'id': '1090519040',
                    'name': 'Behavior Monitoring Configuration Pattern',
                },
                {
                    'id': '1208222021',
                    'name': 'Relevance Rule Pattern (Inspection Pattern)',
                },
                {'id': '1073741840', 'name': 'Spyware/Grayware Pattern'},
                {'id': '1208222099', 'name': 'Advanced Threat Correlation Pattern'},
                {'id': '1073741856', 'name': 'Policy Enforcement Pattern'},
                {'id': '1208221808', 'name': 'Browser Exploit Prevention Pattern'},
                {'id': '1208221779', 'name': 'Damage Recovery Pattern'},
                {'id': '1208221988', 'name': 'Global C&C IP List'},
                {'id': '536870976', 'name': 'IntelliTrap Pattern'},
                {'id': '1208221844', 'name': 'Memory Scan Trigger Pattern (64-bit)'},
                {'id': '1208222307', 'name': ''},
                {'id': '1208090624', 'name': 'Smart Scan Agent Pattern'},
                {
                    'id': '1208221826',
                    'name': 'Behavior Monitoring Detection Pattern (64-bit)',
                },
            ],
        },
        'edrSensor': {
            'endpointGroup': '',
            'connectivity': 'disconnected',
            'lastConnectedDateTime': '2025-02-14T09:24:13',
            'version': '1.2.0.5827',
            'status': 'disabled',
            'advancedRiskTelemetryStatus': 'enabled',
            'componentUpdatePolicy': 'n',
            'componentUpdateStatus': 'onSchedule',
            'patterns': [],
        },
    }


@pytest.fixture
def asset_page(asset):
    return {'totalCount': 1, 'count': 1, 'items': [asset]}
