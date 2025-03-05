import logging
from ipaddress import ip_address
from typing import Any

from tenable.io import TenableIO

from trendmicro.api.session import TrendMicroAPI

from . import __version__ as version


class Transformer:
    """
    Main TrendMicro to TenableOne data transformer.
    """

    counts: dict[str, dict[str, int]]

    def __init__(
        self,
        tvm: TenableIO | None = None,
        trendmicro: TrendMicroAPI | None = None,
    ):
        """
        Initialze transformer

        Args:
            tvm: Optional TVM session to use
            trendmicro: Optional TrendMicro session to use
        """
        self.tvm = (
            tvm
            if tvm
            else TenableIO(
                vendor='Tenable',
                product='TrendMicro2ToneSyncConnector',
                build=version,
            )
        )
        self.trendmicro = trendmicro if trendmicro else TrendMicroAPI()
        self.log = logging.getLogger('Transformer')
        self.counts = {}

    def run(self):
        """
        Run the transformer
        """
        job = self.tvm.sync.create(
            sync_id='tenable_qualys_vm',
        )

        with job:
            self.log.info('Processing TrendMicro assets')
            self.log.debug(f'sync_id: {job.sync_id} uuid: {job.uuid}')
            for asset in self.trendmicro.assets._list():
                t1asset = self.transform_asset(asset)
                
                self.log.debug('Adding asset id=%s to the job' % t1asset['id'])
                job.add(t1asset, object_type='device-asset')

        self.counts['assets'] = {'sent': job.counters['device-asset']['accepted']}

        return self.counts

    def get_os_type(self, value: str | None) -> str | None:
        """
        leverages the OS value to determine the OS type.
        """
        if value and 'windows' in value.lower():
            return 'WINDOWS'
        elif value and 'linux' in value.lower():
            return 'LINUX'
        elif value and 'macos' in value.lower():
            return 'MAC_OS'

    def transform_asset(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Converts the raw Trend Micro asset into a T1-compatable device-asset
        """
        ip_map = {'IPv4Address': 'ip_addresses_v4', 'IPv6Address': 'ip_addresses_v6'}
        ret = {
            'object_type': 'device-asset',
            'asset_class': 'DEVICE',
            'id': str(data['agentGuid']),
            'name': data.get('endpointName'),
            'device': {
                'hardware': {'serial_number': data.get('serialNumber')},
                'system_type': data.get('type'),
                'networking': {
                    'ip_addresses_v4': [],
                    'ip_addresses_v6': [],
                },
                'operating_system': {
                    'type': self.get_os_type(data.get('osPlatform')),
                    'product': {
                        'product_name': data.get('osName'),
                        'version': data.get('osVersion'),
                    },
                },
            },
        }

        for value in data.get('ipAddresses', []):
            if value:
                try:
                    ip = ip_address(value)
                except ValueError as err:
                    raise ValueError(f'{value} is not a valid IP Address') from err
                else:
                    cname = ip.__class__.__name__
                    obj = {'address': str(ip)}
                    if obj not in ret['device']['networking'][ip_map[cname]]:
                        ret['device']['networking'][ip_map[cname]].append(obj)
        return ret
