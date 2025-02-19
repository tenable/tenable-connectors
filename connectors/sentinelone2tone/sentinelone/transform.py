import ipaddress
import logging
from copy import deepcopy
from hashlib import sha256
from typing import Any

import arrow
from tenable.io import TenableIO

from sentinelone.api.session import SentinelOneAPI

from . import __version__ as version


class Transformer:
    counts: dict[str, dict[str, int]]
    app_ids: list[int] = []
    get_findings: bool = True

    def __init__(
        self,
        tvm: TenableIO | None = None,
        s1: SentinelOneAPI | None = None,
    ) -> None:
        """
        Initialize Transformer

        Args:
            tvm (optional): TVM Session to use
            qvm (optional): SentinelOne session to use
        """
        self.tvm = (
            tvm
            if tvm
            else TenableIO(
                vendor='Tenable',
                product='SentinelOne2ToneSyncConnector',
                build=version,
            )
        )
        self.s1 = s1 if s1 else SentinelOneAPI()
        self.log = logging.getLogger('Transformer')
        self.counts = {}

    def run(self, get_findings: bool = True) -> None:
        """
        Transformer Runner

        Args:
            get_findings (optional): Should we import findings into T1 as well?
        """
        self.get_findings = get_findings
        # NOTE: This whole function should likely be broken down further as there is
        #       a lot of looping logic in here that can't easily be tested.  This can
        #       all be adjusted at a later date when SentinelOne comes back to us with
        #       an improved export API that doesn't require the call volume that is
        #       currently necessary.
        job = self.tvm.sync.create(sync_id='tenable_sentinel_one_singularity')

        with job:
            self.log.info('Collecting assets')
            count = 0
            for asset in self.s1.assets.list():
                t1asset = self.asset_transformer(asset)
                self.log.debug('Adding asset id=%s to the job' % t1asset['id'])
                job.add(t1asset, object_type='device-asset')
                count += 1
            self.log.info(f'Imported {count} assets.')

            if not get_findings:
                return

            self.log.info('Collecting findings')
            count = 0
            for app in self.s1.findings.apps_w_risk():
                cves, highest_severity = self.get_cves(app.applicationId)
                if len(cves) == 0:
                    self.log.warning(
                        f'Skipping app_id: {app.applicationId} as it has no cves.'
                    )
                    continue
                base_finding = self.finding_transformer(app, cves, highest_severity)
                for endpoint in self.s1.findings.endpoints_w_apps([app.applicationId]):
                    t1finding = self.finding_endpoint_transformer(
                        base_finding, endpoint
                    )
                    self.log.debug(
                        'Adding finding id=%s to asset id=%s'
                        % (t1finding.get('id'), t1finding.get('asset_id'))
                    )
                    job.add(t1finding, object_type='cve-finding')
                    count += 1
            self.log.info(f'Imported {count} findings.')

        self.counts['assets'] = {'sent': job.counters['device-asset']['accepted']}
        self.counts['findings'] = {'sent': job.counters['cve-finding']['accepted']}
        return self.counts

    def get_os_type(self, value: str | None) -> str | None:
        """
        Convert OS value to determine the OS type.
        Args:
            value (str): os value to convert
        """
        if value and 'windows' in value.lower():
            return 'WINDOWS'
        elif value and 'linux' in value.lower():
            return 'LINUX'
        elif value and 'macos' in value.lower():
            return 'MAC_OS'

    def asset_transformer(self, endpoint: dict | None) -> dict:
        """
        Transform s1 agent record to t1 records
        Args:
            endpoint: A sentinelone agent record from lists() api
        Returns:
            dict
        """
        networking = self.get_network_info(endpoint)
        ret = {
            'object_type': 'device-asset',
            'asset_class': 'DEVICE',
            'id': str(endpoint['id']),
            'name': endpoint['computerName'],
            'device': {
                'hardware': {
                    'serial_number': endpoint['serialNumber'],
                    'cpu': {
                        'count': endpoint['coreCount'],
                        'name': endpoint['cpuId'],
                    },
                    'model': endpoint['modelName'],
                    'ram_mb': endpoint['totalMemory'],
                },
                'operating_system': {
                    'type': self.get_os_type(endpoint['osType']),
                    'build': endpoint['osRevision'],
                    'product': {
                        'product_name': endpoint['osName'],
                    },
                },
                'networking': networking,
                'system_type': endpoint['osType'],
                'uptime_ms': int(arrow.get(endpoint['osStartTime']).timestamp() * 1000)
                if endpoint.get('osSTartTime')
                else None,
            },
            'discovery': {
                'authentication': {
                    'attempted': endpoint.get('scanStartedAt') is not None,
                    'successful': endpoint.get('scanAbortedAt') is None,
                    'type': 'AGENT',
                },
                'first_observed_on': arrow.get(endpoint['createdAt']).datetime,
                'last_observed_on': arrow.get(endpoint['updatedAt']).datetime,
                'assessment_status': 'ATTEMPTED_FINDINGS'
                if self.get_findings
                else 'SKIPPED_FINDINGS',
            },
            'tags': [
                {'name': t['key'], 'value': t['value']}
                for t in endpoint.get('tags', {}).get('sentinelone', [])
            ],
        }
        return ret

    def get_network_info(self, data: dict) -> dict | None:
        """
        Convert s1 network data into t1 format
        Args:
            endpoint: A sentinelone agent record from lists() api
        Returns:
            Dict, None
        """
        ipv4s = [
            ip for intf in data.get('networkInterfaces', []) for ip in intf['inet']
        ]
        ipv6s = [
            ip for intf in data.get('networkInterfaces', []) for ip in intf['inet6']
        ]

        for key in ('lastIpToMgmt', 'externalIp'):
            if value := data.get(key):
                ip = ipaddress.ip_address(value)
                if isinstance(ip, ipaddress.IPv4Address):
                    ipv4s.append(value)
                if isinstance(ip, ipaddress.IPv6Address):
                    ipv6s.append(value)
        return {
            'ip_addresses_v4': [{'address': i} for i in set(ipv4s)],
            'ip_addresses_v6': [{'address': i} for i in set(ipv6s)],
            'mac_addresses': [
                intf['physical'] for intf in data.get('networkInterfaces', [])
            ],
            'network_group_id': '664ee720-9759-41d4-9a44-ed7474a4c789',
        }

    def finding_endpoint_transformer(
        self,
        base_finding: dict[str, Any],
        endpoint: dict[str, Any],
        **kwargs,
    ) -> dict:
        """
        Add endpoint info to the base finding so we can submit to t1
        Args:
            base_finding (dict): the base finding obect we will copy for each endpoint.
            endpoint (dict): the endpoint data from s1 api
        Returns:
            Dict
        """
        ret = deepcopy(base_finding)
        ret['asset_id'] = str(endpoint['endpointId'])
        ret['id'] = sha256(
            f'{ret["asset_id"]}::{ret["id"]}'.encode('utf-8')
        ).hexdigest()
        ret['discovery'] = {
            'first_observed_at': arrow.get(
                endpoint['applicationDetectionDate']
            ).datetime,
            'last_observed_on': arrow.get(endpoint['lastScanDate']).datetime,
        }
        return ret

    def get_cves(self, app_id: int) -> tuple[list, int]:
        """
        Get cves related to a specific app_id and convert to simple list of cve values.
        Args:
            app_id (int): S1 Application ID to get related CVEs for
        Returns:
            List
        """
        sev_switch = {'NONE': 1, 'LOW': 2, 'MEDIUM': 3, 'HIGH': 4, 'CRITICAL': 5}
        cves = list()
        severities = set()
        severities.add(1)
        for app_cve in self.s1.findings.cves_on_app([app_id]):
            severities.add(sev_switch[str(app_cve.get('severity', 'NONE')).upper()])
            cves.append(app_cve.cveId)
        return cves, max(severities)

    def finding_transformer(
        self,
        app: dict[str, Any],
        cves: list[str],
        severity: int,
        **kwargs,
    ) -> dict:
        """
        Create a basic finding that we can copy in just endpoint data and add to job
        Args
            app (dict): the s1 application data object
            cves (list): the list of cve-ids for this s1 application
            severity (int): the highest severity id for the CVEs related to this s1 app
        Returns:
            Dict
        """
        sev_switch = {1: 'NONE', 2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL'}
        resp = {
            'object_type': 'cve-finding',
            'state': 'ACTIVE',
            'id': app['applicationId'],
            'cve': {'cves': cves[:512]},
            'exposure': {'severity': {'level': sev_switch.get(severity)}},
        }
        return resp
