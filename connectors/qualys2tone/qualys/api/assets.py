"""
Asset Handling API Module for Qualys
"""

from typing import Optional

import arrow
from arrow.arrow import Arrow
from restfly.endpoint import APIEndpoint

from .models.asset import Host
from .streaming import xml_handler


class AssetsAPI(APIEndpoint):
    _path = 'asset/host/'

    def _list(
        self,
        compliance_enabled: bool,
        page_size: Optional[int] = 10000,
        since: Optional[Arrow | str] = None,
        **kwargs,
    ) -> xml_handler:
        """
        Get all hosts last seen with vuln findings

        Args:
            compliance_enabled (bool): if we should get compliance data or vuln data
            page_size (int, optional): the page size we want to download
            since (Arrow|str, optional):
                An arrow object or time string to pull data since.
                If None we pull api default.
        Returns:
            QualysIterator
        Docs:
            page 535
        """

        params = {
            'action': 'list',
            #'os_hostname': 1,
            'show_asset_id': 1,
            #'detail': 'All', #option: {Basic|Basic/AGs|All|All/AGs | None}
            'show_ars': 1,
            'show_tags': 1,
            'show_ars_factors': 1,
            'show_trurisk': 1,
            'show_trurisk_factors': 1,
            #'host_metadata': 'all',  # List cloud and non-cloud
            'show_cloud_tags': 1,
            'truncation_limit': page_size,
            'compliance_enabled': 1 if compliance_enabled else None,
        }

        if since is not None:
            # TODO check if we can move to detection_ since from vulns api
            # format YYYY-MM-DD[THH:MM:SSZ]
            if compliance_enabled:
                # Set compliance data since param
                params['compliance_scan_since'] = arrow.get(since).isoformat()
            else:
                # set vuln data since param
                params['vm_scan_since'] = arrow.get(since).isoformat()

        return xml_handler(self._api, self._path, params, Host, 'HOST')

    def vuln(self, since: Optional[Arrow | str] = None, **kwargs) -> xml_handler:
        """
        Get all hosts last seen with vuln findings

        Args:
            since optional(Arrow:str):
                An arrow object or time string to pull data since. If None we pull
                api default.
        Returns:
            QualysIterator
        """
        return self._list(compliance_enabled=False, since=since, **kwargs)

    def compliance(self, since: Optional[Arrow | str] = None, **kwargs) -> xml_handler:
        """
        Get all hosts last seen with compliance findings

        Args:
            since optional(Arrow:str):
                An arrow object or time string to pull data
                since. If None we pull api default.
        Returns:
            QualysIterator
        """
        raise NotImplementedError('This feature has not been implemented yet.')
        # return self._list(compliance_enabled=True,since=since, **kwargs)
