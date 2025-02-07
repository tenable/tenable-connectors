import logging
from hashlib import sha256
from ipaddress import IPv4Address, ip_address
from typing import Any

import arrow
from restfly.utils import trunc
from tenable.io import TenableIO

from msdefender import MSDefenderAPI


class Transformer:
    counts: dict[str, dict[str, int]]
    get_findings: bool = True

    def __init__(
        self,
        tvm: TenableIO | None = None,
        defender: MSDefenderAPI | None = None,
    ) -> None:
        """ """
        self.tvm = tvm if tvm else TenableIO()
        self.defender = defender if defender else MSDefenderAPI()
        self.log = logging.getLogger('Transformer')
        self.counts = {}

    def run(self, get_findings: bool = True) -> None:
        self.get_findings = get_findings
        job = self.tvm.sync.create(sync_id='tenable_microsoft_defender')

        with job:
            for asset in self.defender.assets.list():
                t1asset = self.transform_asset(asset)
                self.log.debug('Adding asset id=%s to the job' % t1asset['id'])
                job.add(t1asset, object_type='device-asset')
            if not get_findings:
                return
            for vuln in self.defender.findings.vulns():
                finding = self.transform_finding(vuln)
                self.log.debug(
                    'Adding finding id=%s to asset id=%s'
                    % (finding['id'], vuln['machineId'])
                )
                job.add(finding, object_type='cve-finding')

        self.counts['assets'] = {'sent': job.counters['device-asset']['accepted']}
        self.counts['findings'] = {'sent': job.counters['cve-finding']['accepted']}
        return self.counts

    def get_network_info(self, data: dict[str, Any]) -> dict[str, list[str]]:
        """
        Parses the ip addresses list within the machine info and attempts to collate the
        information into the IPv4, IPv6, and Mac Addresses.  Returns a unique list of each
        type.
        """
        resp = {'ipv6': [], 'ipv4': [], 'macs': []}
        for item in data:
            # Attempt to load the IP address using the ip_address helper function provided
            # within the ipaddress package.  If something happens to go wrong, we will
            # ignore the value (which isn't valid anyway) and instead pass a link-local
            # address instead.
            try:
                address = ip_address(item['ipAddress'])
            except ValueError:
                address = IPv4Address('127.0.0.1')

            # MSDefender's API returns a non-RFC Mac address format.  We will convert
            # the list of hex values into the commonly used IEEE-802 standard separated
            # by colons.
            mac = '00:00:00:00:00:00'
            if item['macAddress']:
                mac = ':'.join(
                    [
                        item['macAddress'][i : i + 2]
                        for i in range(0, len(item['macAddress']), 2)
                    ]
                )

            # If the address hasn't been captured yet and is not a link-local or loopback
            # address, we will then add the address to the appropriate version list.
            if str(address) not in resp[f'ipv{address.version}'] and not (
                address.is_link_local or address.is_loopback
            ):
                resp[f'ipv{address.version}'].append(str(address))

            # If the Mac address isn't a zeroed address and has not already been captured,
            # we will then appent it to the mac list.
            if mac != '00:00:00:00:00:00' and mac not in resp['macs']:
                resp['macs'].append(mac)

        # return the results to the caller.
        return resp

    def derive_system_type(self, system_type: str) -> str:
        """
        Attempts to derive the system type as required by the T1 Sync API.  If unsuccessful
        then we will return 'UNKNOWN'.
        """
        type_map = {'windows': 'WINDOWS', 'linux': 'LINUX', 'macos': 'MAC_OS'}
        for key, value in type_map.items():
            if system_type and system_type.lower() in key:
                return value
        return 'UNKNOWN'

    def transform_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        """
        Converts an MS Defender machine into a T1 compatable asset format.
        """
        network_info = self.get_network_info(asset['ipAddresses'])

        # The external address for the machine is stored in a separate attribute, so we will
        # attempt to capture and add the address to the appropriate ip listing if we haven't
        # already captured the address.
        try:
            ext_address = ip_address(asset['lastExternalIpAddress'])
        except ValueError:
            pass
        else:
            if str(ext_address) not in network_info[f'ipv{ext_address.version}']:
                network_info[f'ipv{ext_address.version}'].append(str(ext_address))
        for key in ('osBuild', 'osPlatform', 'version'):
            asset[key] = (
                str(asset.get(key)) if asset.get(key, 'Other') != 'Other' else None
            )
        ret = {
            'object_type': 'device-asset',
            'id': asset['id'],
            'name': asset['computerDnsName'],
            'labels': [label for label in asset.get('machineTags', []) if label],
            'device': {
                'networking': {
                    'fqdns': [{'value': asset['computerDnsName']}]
                    if asset['computerDnsName']
                    else None,
                    'ip_addresses_v4': [
                        {'address': i} for i in network_info['ipv4'] if i
                    ],
                    'ip_addresses_v6': [
                        {'address': i} for i in network_info['ipv6'] if i
                    ],
                    'mac_addresses': network_info.get('macs', []),
                },
                'operating_system': {
                    'build': asset['osBuild'],
                    'product': {
                        'product_name': asset['osPlatform'],
                        'version': asset['version'],
                    },
                    'type': self.derive_system_type(asset['osPlatform']),
                },
            },
            'discovery': {
                'first_observed_on': arrow.get(asset['firstSeen']).datetime,
                'last_observed_on': arrow.get(asset['lastSeen']).datetime,
                'assessment_status': 'ATTEMPTED_FINDINGS'
                if self.get_findings
                else 'SKIPPED_FINDINGS',
            },
            'exposure': {'criticality': {'level': str(asset['exposureLevel']).upper()}},
        }
        # if len(network_info['macs']) > 0:
        #    ret['device']['networking']['mac_addresses'] = network_info['macs']
        # if 'machineTags' in asset and len(asset['machineTags']) > 0:
        #    labels = [label for label in asset['machineTags'] if label]
        #    if labels:
        #        ret['labels'] = labels
        return ret

    def transform_finding(self, finding: dict) -> dict:
        """
        Converts an MS Defender finding into a T1 compatable format.
        """
        return {
            'object_type': 'cve-finding',
            'asset_id': finding['machineId'],
            'id': str(sha256(finding['id'].encode('utf-8')).hexdigest()),
            'cve': {'cves': [finding['cveId']]},
            'exposure': {'severity': {'level': str(finding['severity'].upper())}},
            'observations': {
                'software': [
                    {
                        'product': {
                            'product_name': trunc(str(finding['productName']), 32),
                            'vendor_name': trunc(str(finding['productVendor']), 32),
                            'version': trunc(str(finding['productVersion']), 32),
                        },
                    },
                ],
            },
        }
