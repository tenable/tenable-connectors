import ipaddress
import logging
from typing import Any

import arrow
from restfly.utils import trunc
from tenable.io import TenableIO

from . import __version__ as version
from .api.session import CrowdStrikeAPI


class Transformer:
    counts: dict[str, dict[str, int]]
    get_findings: bool = False

    def __init__(
        self,
        tvm: TenableIO | None = None,
        crwd: CrowdStrikeAPI | None = None,
    ) -> None:
        """
        Initialize the transformer.

        Args:
            tvm: Optional TenableIO session to use.
            crwd: Optional CrowdStrikeAPI session to use.
        """
        self.tvm = (
            tvm
            if tvm
            else TenableIO(
                vendor='Tenable',
                product='CrowdStrike2ToneSyncConnector',
                build=version,
            )
        )
        self.crwd = crwd if crwd else CrowdStrikeAPI()
        self.log = logging.getLogger('Transformer')
        self.counts = {}

    def run(
        self,
        get_findings: bool = True,
        last_seen_days: int = 1,
    ) -> dict[str, dict[str, int]]:
        """
        Main entry point for the transformer.

        Args:
            get_findings (bool):
                Should we import findings into T1 as well?
            last_seen_days (int):
                The number of days to go back when collecting assets and findings.

        Returns:
            dict: The counts of assets and findings imported.
        """
        job = self.tvm.sync.create(sync_id='tenable_crowdstrike_falcon')
        with job:
            # Process the assets
            for asset in self.crwd.assets.list(last_seen_days=last_seen_days):
                t1asset = self.transform_asset(asset)
                self.log.debug('Adding asset id=%s to the job' % t1asset['id'])
                job.add(t1asset, object_type='device-asset')

            self.counts['assets'] = {'sent': job.counters['device-asset']['accepted']}

            # Process the findings
            if get_findings:
                for vuln in self.crwd.findings.vulns(last_seen_days=last_seen_days):
                    finding = self.transform_finding(vuln)
                    self.log.debug(
                        'Adding finding id=%s to asset id=%s'
                        % (finding['id'], vuln['aid'])
                    )
                    job.add(finding, object_type='cve-finding')
                self.counts['findings'] = {
                    'sent': job.counters['cve-finding']['accepted']
                }
        return self.counts

    def derive_system_type(self, system_type: str) -> str:
        """
        Attempts to derive the system type as required by the T1 Sync API.
        If unsuccessful then we will return 'UNKNOWN'.
        """
        type_map = {'windows': 'WINDOWS', 'linux': 'LINUX', 'macos': 'MAC_OS'}
        for key, value in type_map.items():
            if key in system_type.lower():
                return value
        return 'UNKNOWN'

    def transform_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        """
        Converts a CS machine into a T1 compatible asset format.
        """
        ip_map = {'IPv4Address': 'ip_addresses_v4', 'IPv6Address': 'ip_addresses_v6'}
        ret = {
            'object_type': 'device-asset',
            'id': asset['device_id'],
            'name': asset.get('hostname', None),
            'external_ids': [
                {'qualifier': 'crowdstrike-agent-id', 'value': asset['device_id']}
            ],
            'device': {
                'networking': {
                    'mac_addresses': [asset.get('mac_address')]
                    if asset.get('mac_address')
                    else None,
                    'ip_addresses_v4': [],
                    'ip_addresses_v6': [],
                },
                'hardware': {
                    'serial_number': asset.get('serial_number'),
                    'bios': {
                        'manufacturer': asset.get('bios_manufacturer', None),
                        'version': trunc(asset.get('bios_version'), 32)
                        if asset.get('bios_version')
                        else None,
                    },
                },
                'operating_system': {
                    'type': self.derive_system_type(asset.get('platform_name', '')),
                },
            },
            'labels': asset.get('tags'),
            'discovery': {
                'first_observed_on': arrow.get(asset['first_seen']).datetime,
                'last_observed_on': arrow.get(asset['last_seen']).datetime,
                'assessment_status': 'ATTEMPTED_FINDINGS'
                if self.get_findings
                else 'SKIPPED_FINDINGS',
            },
        }
        for key in ('external_ip', 'local_ip'):
            value = asset.get(key)
            if value:
                try:
                    ip = ipaddress.ip_address(value)
                except ValueError:
                    self.log.debug(f'{ip} is not a valid IP Address')
                else:
                    cname = ip.__class__.__name__
                    obj = {'address': str(ip)}
                    if obj not in ret['device']['networking'][ip_map[cname]]:
                        ret['device']['networking'][ip_map[cname]].append(obj)
        return ret

    def transform_finding(self, finding: dict) -> dict:
        """
        Converts a CrowdStrike finding into a T1 compatible format.

        This function takes a CrowdStrike finding and transforms it into a
        T1-compatible CVE finding. It extracts the relevant information from the
        finding, such as the asset ID, state, discovery timestamps, and CVE ID.
        It then returns a dictionary that is compatible with the T1 API.

        :param finding: A dictionary containing the CrowdStrike vulnerability.
        :return: A dictionary containing the transformed finding.
        """
        # Map CrowdStrike finding status to T1 finding state
        status_switch = {
            'open': 'ACTIVE',
            'reopen': 'REOPENED',
        }

        # Extract the relevant information from the finding
        observations = {}
        if finding.get('apps'):
            observations['software'] = []
            for app in finding['apps']:
                observations['software'].append(
                    {
                        'product': {
                            # Normalize the product name and vendor to 32 characters
                            'product_name': app.get('vendor_normalized'),
                            'vendor_name': app.get('product_name_version'),
                            'version': app.get('product_name_normalized'),
                        }
                    }
                )
        cve_id = finding.get('cve', {}).get('id')
        severity = finding.get('cve', {}).get('severity')
        # Normalize the severity
        if severity:
            severity = severity if severity != 'UNKNOWN' else 'NONE'

        # Return the transformed finding
        return {
            'object_type': 'cve-finding',
            'asset_id': finding['aid'],
            'definition_urn': f'urn:crowdstrike:{finding["vulnerability_id"]}',
            # Use the status switch to map the CrowdStrike finding status to
            # T1 finding state
            'state': status_switch.get(finding.get('status', ''), 'ACTIVE'),
            'discovery': {
                'first_observed_at': finding.get('created_timestamp'),
                'last_observed_on': finding.get('updated_timestamp'),
            },
            'id': finding['id'],
            'cve': {'cves': [cve_id]} if cve_id else None,
            'observations': observations if observations else None,
            'exposure': {'severity': {'level': severity} if severity else None},
        }
