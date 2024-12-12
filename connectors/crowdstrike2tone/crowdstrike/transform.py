import ipaddress
import logging
from typing import Any

import arrow
from restfly.utils import trunc
from tenable.io import TenableIO

from crowdstrike import CrowdStrikeAPI


class Transformer:
    def __init__(
        self,
        tvm: TenableIO | None = None,
        crwd: CrowdStrikeAPI | None = None,
    ) -> None:
        """ """
        self.tvm = tvm if tvm else TenableIO()
        self.crwd = crwd if crwd else CrowdStrikeAPI()
        self.log = logging.getLogger("Transformer")

    def run(self, get_findings: bool = True, last_seen_days: int = 1) -> None:
        with self.tvm.sync.create(
            sync_id="tenable_crowdstrike_falcon",
            vendor="tenable",
            sensor="crowdstrike",
        ) as job:
            for asset in self.crwd.assets.list(last_seen_days=last_seen_days):
                t1asset = self.transform_asset(asset)
                self.log.debug("Adding asset id=%s to the job" % t1asset["id"])
                job.add(t1asset, object_type="device-asset")
            if not get_findings:
                return
            raise NotImplementedError()
            # for vuln in self.crwd.findings.vulns():
            #    finding = self.transform_finding(vuln)
            #    self.log.debug(
            #        'Adding finding id=%s to asset id=%s'
            #        % (finding['id'], vuln['machineId'])
            #    )
            #    job.add(finding, object_type='cve-finding')

    def derive_system_type(self, system_type: str) -> str:
        """
        Attempts to derive the system type as required by the T1 Sync API.  If unsuccessful
        then we will return 'UNKNOWN'.
        """
        type_map = {"windows": "WINDOWS", "linux": "LINUX", "macos": "MAC_OS"}
        for key, value in type_map.items():
            if system_type.lower() in key:
                return value
        return "UNKNOWN"

    def transform_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        """
        Converts a CS machine into a T1 compatable asset format.
        """
        ip_map = {"IPv4Address": "ip_addresses_v4", "IPv6Address": "ip_addresses_v6"}
        ret = {
            "object_type": "device-asset",
            "id": asset["device_id"],
            "name": asset.get("hostname", None),
            "device": {
                "networking": {
                    "mac_addresses": [asset.get("mac_address")]
                    if asset.get("mac_address")
                    else None,
                    "ip_addresses_v4": [],
                    "ip_addresses_v6": [],
                },
                "hardware": {
                    "serial_number": asset.get("serial_number"),
                    "bios": {
                        "manufacturer": asset.get("bios_manufacturer", None),
                        "version": trunc(asset.get("bios_version"), 32)
                        if asset.get("bios_version")
                        else None,
                    },
                },
                "operating_system": {
                    "type": self.derive_system_type(asset.get("platform_name", "")),
                },
            },
            "labels": asset.get("tags"),
            "discovery": {
                "first_observed_at": arrow.get(asset["first_seen"]).datetime,
                "last_observed_on": arrow.get(asset["last_seen"]).datetime,
            },
        }
        for key in ("external_ip", "local_ip"):
            value = asset.get(key)
            if value:
                try:
                    ip = ipaddress.ip_address(value)
                except ValueError:
                    self.log.debug(f"{ip} is not a valid IP Address")
                else:
                    cname = ip.__class__.__name__
                    obj = {"address": str(ip)}
                    if obj not in ret["device"]["networking"][ip_map[cname]]:
                        ret["device"]["networking"][ip_map[cname]].append(obj)

        #        if 'external_ip' in asset or 'local_ip' in asset:
        #            ipv4s = []
        #            if 'external_ip' in asset:
        #                ipv4s.append({'address': asset['external_ip']})
        #            if 'local_ip' in asset:
        #                ipv4s.append({'address': asset['local_ip']})
        #            if 'networking' not in ret['device']:
        #                ret['device'] = {'networking': {}}
        #            if len(ipv4s) > 0:
        #                ret['device']['networking']['ip_addresses_v4'] = ipv4s
        #        if 'tags' in asset and len(asset['tags']) > 0:
        #            ret['labels'] = [label for label in asset['tags'] if label]
        #        if 'mac_address' in asset:
        #            if 'networking' not in ret['device']:
        #                ret['device'] = {'networking': {}}
        #            ret['device']['networking']['mac_addresses'] = [asset.get('mac_address')]
        return ret

    def transform_finding(self, finding: dict) -> dict:
        """
        Converts an MS Defender finding into a T1 compatable format.
        """
        raise NotImplementedError()
        # return {
        #    'object_type': 'cve-finding',
        #    'asset_id': finding['machineId'],
        #    'id': str(uuid3(self.NAMESPACE, finding['id'])),
        #    'cve': {'cves': [finding['cveId']]},
        #    'exposure': {'severity': {'level': str(finding['severity'].upper())}},
        #    'observations': {
        #        'software': [
        #            {
        #                'product': {
        #                    'product_name': trunc(str(finding['productName']), 32),
        #                    'vendor_name': trunc(str(finding['productVendor']), 32),
        #                    'version': trunc(str(finding['productVersion']), 32),
        #                },
        #            },
        #        ],
        #    },
        # }


#
