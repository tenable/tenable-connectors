import logging
from hashlib import sha256
from ipaddress import IPv4Address, ip_address
from typing import Any

from restfly.utils import trunc
from tenable.io import TenableIO

from rapid7.api.session import Rapid7API

from . import __version__ as version
from .database import Knowledgebase, init_db


class Transformer:
    counts: dict[str, dict[str, int]]

    def __init__(
        self,
        db_uri: str = 'sqlite:///cache.db',
        tvm: TenableIO | None = None,
        rapid7: Rapid7API | None = None,
    ) -> None:
        """
        Initialze transformer

        Args:
            db_uri: The cache database location
            tvm: Optional TVM session to use
            rapid7: Optional Rapid7 session to use
        """
        self.tvm = (
            tvm
            if tvm
            else TenableIO(
                vendor='Tenable',
                product='Rapid72ToneSyncConnector',
                build=version,
            )
        )
        self.rapid7 = rapid7 if rapid7 else Rapid7API()
        self.log = logging.getLogger('Transformer')
        self.db = init_db(db_uri)
        self.counts = {}

    def cache_knowledgebase(self) -> None:
        """
        Stores CVE metadata into the cache database

        Queries the Qualys Knowldegbase API and stores the CVE data into the cache for
        later use as the findings report does not contain the CVE data.
        """
        self.log.info('Collecting Rapid7 KB meta data')
        counter = 0
        records = 0
        with self.db.session() as session:
            for vuln_info in self.rapid7.findings.list_findings():
                cves_data = vuln_info.get('cves', [])
                session.add(
                    Knowledgebase(
                        id=vuln_info['id'],
                        cves=cves_data,
                        severity=vuln_info['severity'],
                    )
                )
                counter += 1
                if counter >= 1000:
                    session.commit()
                    counter = 0
                    records += 1000
                    self.log.info(f'Committed {records} records')

            self.log.info(f'Committed {records + counter} records')
            session.commit()

    def run(self, get_findings: bool = True) -> dict[str, dict[str, int]]:
        job = self.tvm.sync.create(sync_id='tenable_sentinel_one_singularity')

        with job:
            vuln_asset_ids = []
            for asset in self.rapid7.assets.list():
                # Generate list of assets that have vulnerabilities
                if asset.vulnerabilities.total:
                    vuln_asset_ids.append(asset.id)
                t1asset = self.transform_asset(asset)
                self.log.debug(f'Adding asset id={t1asset["id"]} to the job')
                job.add(t1asset, object_type='device-asset')
            self.counts['assets'] = {'sent': job.counters['device-asset']['accepted']}

            if get_findings and len(vuln_asset_ids) > 0:
                self.cache_knowledgebase()
                for asset_id in vuln_asset_ids:
                    for vuln in self.rapid7.findings.list_asset_findings(asset_id):
                        if vuln.get('status') == 'vulnerable':
                            finding = self.transform_finding(vuln, asset_id)
                            self.log.debug(
                                f'Adding finding id={finding["id"]} to '
                                + f'asset id={asset_id}'
                            )
                            job.add(finding, object_type='cve-finding')
                self.counts['findings'] = {
                    'sent': job.counters['cve-finding']['accepted']
                }

        return self.counts

    def get_network_info(self, addresses: dict[str, Any]) -> dict[str, Any]:
        """
        Takes a list of IP addresses and parses them into a dictionary of ip addresses
        (v4 and v6) and mac addresses.

        Args:
            addresses: A list of dictionaries containing ip addresses and mac
            addresses.

        Returns:
            A dictionary of ip addresses and mac addresses.
        """
        network_info = {'ipv4': [], 'ipv6': [], 'macs': []}

        for address in addresses:
            try:
                ip_add = ip_address(address['ip'])  # Check for ip_add validity and type
            except ValueError:
                ip_add = IPv4Address('127.0.0.1')

            if str(ip_add) not in network_info[f'ipv{ip_add.version}'] and not (
                ip_add.is_link_local or ip_add.is_loopback
            ):  # Assign to IPv4 or IPv6 address list if it is not local or loopback
                network_info[f'ipv{ip_add.version}'].append(str(ip_add))

            mac = address['mac']
            if mac and mac not in network_info['macs']:
                network_info['macs'].append(str(mac.lower()))

        return network_info

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
        Transforms a Rapid7 InsightVM asset into a Tenable.io device-asset.

        Args:
            asset (dict[str, Any]): The asset to transform.

        Returns:
            dict[str, Any]: The transformed asset.
        """
        network_info = self.get_network_info(asset['addresses'])
        asset_os = asset.get('osFingerprint')
        asset_os_cpe = asset_os.get('cpe') if asset_os else None

        ret = {
            'object_type': 'device-asset',
            'asset_class': 'DEVICE',
            'device': {
                'networking': {
                    'fqdns': [{'value': host} for host in asset['hostNames']]
                    if 'hostNames' in asset.keys()
                    else None,
                    'ip_addresses_v4': [{'address': i} for i in network_info['ipv4']]
                    if network_info['ipv4']
                    else None,
                    'ip_addresses_v6': [{'address': i} for i in network_info['ipv6']]
                    if network_info['ipv6']
                    else None,
                    'mac_addresses': network_info.get('macs'),
                },
                'operating_system': {
                    'confidence': int(float(asset['osCertainty']) * 100)
                    if asset['osCertainty']
                    else None,
                    'product': {
                        'product_name': trunc(asset_os.get('product'), 32),
                        'vendor_name': trunc(asset_os.get('vendor'), 32),
                        'cpe': asset_os.get('v2.3'),
                        'version': trunc(asset_os.get('version'), 32),
                    }
                    if asset_os_cpe
                    else None,
                    'type': self.derive_system_type(asset_os.get('family', 'UNKNOWN')),
                },
                # Possible values are: unknown, guest, hypervisor, physical, mobile
                'system_type': asset.get('type'),
            },
            'id': str(asset['id']),
            'name': trunc(asset.hostname, 128) if asset.get('hostname') else None,
        }

        return ret

    def transform_finding(self, vuln: dict[str, Any], asset_id: int) -> dict[str, Any]:
        """
        Converts a Rapid7 vulnerability into a Tenable.io CVE finding.

        Args:
            vuln (dict): The Rapid7 vulnerability object for asset id.
            vuln_info (dict): The Rapid7 vulnerability object having details of vulnerability.
            asset_id (int): The Tenable.io asset_id for the asset this finding is for.

        Returns:
            dict: A dictionary representing a Tenable.io CVE finding.
        """  # noqa: E501
        sev_switch = {'Moderate': 'MEDIUM', 'Severe': 'HIGH', 'Critical': 'CRITICAL'}
        with self.db.session() as session:
            kb = (
                session.query(Knowledgebase)
                .filter(Knowledgebase.id == vuln['id'])
                .one()
            )

            ret = {
                'object_type': 'cve-finding',
                'asset_id': str(asset_id),
                'cve': {'cves': kb.cves} if len(kb.cves) > 0 else None,
                'definition_urn': f'urn:rapid7:{vuln["id"]}',
                'discovery': {
                    'first_observed_at': vuln.get('since'),
                },
                'id': str(sha256(vuln['id'].encode('utf-8')).hexdigest()),
                'state': 'ACTIVE',
                'exposure': {'severity': {'level': sev_switch.get(kb.severity)}},
            }

            return ret
