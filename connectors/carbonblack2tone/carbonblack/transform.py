import logging
from typing import Any
from tenable.io import TenableIO
from carbonblack import CarbonBlackAPI
from ipaddress import ip_address, IPv4Address, IPv6Address
from . import __version__ as version


class Transformer:
    counts: dict[str, dict[str, int]]

    def __init__(
        self,
        tvm: TenableIO | None = None,
        cba: CarbonBlackAPI | None = None,
    ) -> None:
        self.tvm = (
            tvm
            if tvm
            else TenableIO(
                vendor='Tenable',
                product='CarbonBlack2ToneSyncConnector',
                build=version,
            )
        )
        self.cba = cba if cba else CarbonBlackAPI()
        self.log = logging.getLogger('Transformer')
        self.counts = {}

    def run(
        self,
        import_findings: bool = False,
    ) -> dict[str, dict[str, int]]:
        job = self.tvm.sync.create(
            # sync_id="tenable_carbon_black",
            sync_id='tenable_microsoft_defender'
        )
        with job:
            for asset in self.cba.assets.list():
                t1asset = self.transform_asset(asset)
                self.log.debug(f'Adding asset_id={t1asset["id"]} to the job')
                job.add(t1asset, object_type='device-asset')
            self.counts['assets'] = {'sent': job.counters['device-asset']['accepted']}
            if import_findings:
                for finding in self.cba.findings.list():
                    # Skip the finding if affected_assets is None in the record
                    if not finding['affected_assets']:
                        continue
                    for asset in finding['affected_assets']:
                        t1finding = self.transform_finding(finding, asset)
                        self.log.debug(
                            f'Adding findings for asset_id={asset}, vuln_id={t1finding.get("vuln_info", {}).get("cve_id")} to the job'
                        )
                        job.add(t1finding, object_type='cve-finding')
                self.counts['findings'] = {
                    'sent': job.counters['cve-finding']['accepted']
                }

        return self.counts

    def derive_system_type(self, system_type: str) -> str:
        """
        Attempts to derive the system type as required by the T1 Sync API.  If unsuccessful
        then we will return 'UNKNOWN'.
        Args:
            system_type (str, required):
                The system type from the response
        Returns:
            str:
                Mapped system type
        """
        type_map = {'WINDOWS': 'WINDOWS', 'LINUX': 'LINUX', 'MAC': 'MAC_OS'}
        system_type = system_type.upper()
        return type_map[system_type] if system_type in type_map else 'UNKNOWN'

    def derive_severity(self, severity: str) -> str:
        """
        Attempts to derive the severity as required by the T1 Sync API.If unsuccessful
        then we will return 'NONE'.
        Args:
            severity (str, required):
                The severity from the response
        Returns:
            str:
                Mapped Severity
        """
        severity_map = {
            'CRITICAL': 'CRITICAL',
            'MODERATE': 'MEDIUM',
            'IMPORTANT': 'HIGH',
            'LOW': 'LOW',
        }
        return (
            severity_map[severity.upper()]
            if severity_map.get(severity.upper())
            else 'NONE'
        )

    def format_mac_address(self, address: str) -> str:
        """Format the string value to the valid mac address.
        Args:
            address (str, required):
                mac_address from the response
        Returns:
            str: Converted string to valid MAC address
        """
        if address:
            mac_address = ':'.join(
                address[i : i + 2] for i in range(0, len(address), 2)
            )
            return mac_address.split(' ')
        else:
            return None

    def validate_ip_address(self, ip: str, is_ipv4: bool = True) -> dict:
        """Validate and return the ip address based on is_ipv4 flag
        Args:
            ip (str, required):
                last_internal_ip_address from the response
            is_ipv4 (bool, optional):
                Determine the type of validation to perform for IPV4 or IPV6
        Returns:
            dict:
                dict object with valid ip address"""
        try:
            if is_ipv4:
                return (
                    [{'address': ip_address(ip)}]
                    if type(ip_address(ip)) is IPv4Address
                    else None
                )
            else:
                return (
                    [{'address': ip_address(ip)}]
                    if type(ip_address(ip)) is IPv6Address
                    else None
                )

        except ValueError:
            return None

    def transform_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        """
        Converts a carbon balck device into a T1 compatable asset format.
        Args:
            asset (dict, required):
                Asset object from the API response
        Returns:
            dict:
                T1 acceptable asset dict
        """
        return {
            'object_type': 'device-asset',
            'id': str(asset['id']),
            'name': asset['name'] if asset.get('name') else '',
            'device': {
                'networking': {
                    'ip_addresses_v4': self.validate_ip_address(
                        asset['last_internal_ip_address']
                    ),
                    'ip_addresses_v6': self.validate_ip_address(
                        asset['last_internal_ip_address'], is_ipv4=False
                    ),
                    'mac_addresses': self.format_mac_address(asset['mac_address']),
                },
                'operating_system': {
                    'product': {
                        'version': asset['os_version'].lower()
                        if asset.get('os_version')
                        else '',
                        'product_name': asset['os'].lower() if asset.get('os') else '',
                    },
                    'type': self.derive_system_type(asset.get('os', '')),
                },
                'system_type': asset['deployment_type'].lower()
                if asset.get('deployment_type')
                else '',
            },
            'exposure': {
                'criticality': {
                    'level': self.derive_severity(asset.get('vulnerability_severity'))
                }
                if asset.get('vulnerability_severity')
                else None
            },
        }

    def transform_finding(self, finding: dict, asset: str) -> dict:
        """
        Converts an Carbon Black vulnerability into a T1 compatable format.
        Args:
            finding (dict, required):
                Finding object from the API response
        Returns:
            dict:
                T1 acceptable finding dict
        """
        product_info = finding.get('product_info', {})
        vuln_info = finding.get('vuln_info')
        cve_id = vuln_info['cve_id']
        return {
            'object_type': 'cve-finding',
            'asset_id': asset,
            'id': cve_id,
            'definition_urn': f'urn:carbonblack:{cve_id}',
            'cve': {'cves': [cve_id]},
            'observations': {
                'software': [
                    {
                        'product': {
                            'product_name': product_info.get('product', ''),
                            'vendor_name': product_info.get('vendor', ''),
                            'version': product_info.get('version', ''),
                        }
                    }
                ]
            },
            'exposure': {
                'severity': {
                    'level': self.derive_severity(vuln_info.get('severity', ''))
                }
            },
            'state': 'ACTIVE',
        }
