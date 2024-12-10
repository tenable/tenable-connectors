"""
Finding/Vulnerability handling API module for Qualys
"""

from typing import List, Literal

import arrow
from restfly.endpoint import APIEndpoint

from .models.asset import Host
from .streaming import xml_handler


class FindingsAPI(APIEndpoint):
    _path = 'asset/host/vm/detection/'

    def _list(
        self,
        compliance_enabled: bool = False,
        since: int | None = None,
        include_ignored: bool = False,
        include_disabled: bool = False,
        status: List[Literal['New', 'Active', 'Re-Opened', 'Fixed']] | None = None,
        severities: List[Literal[1, 2, 3, 4, 5]] | None = None,
        filter_superseded_qids: bool = True,
        page_size: int = 10000,
        **kwargs,
    ) -> xml_handler:
        """
        Collect vulns or compliance findings
        Args:
            compliance_enabled (bool):
                When True we only get compliance findings. When False we only get
                vuln findings.
            since (Arrow|str, optional):
                An arrow object or time string to pull data since. If None we pull
                api default.
            include_ignored (bool, optional): include ignored QIDs in results
            include_disabled (bool, optional): include disabled QIDs in results
            status (list(str), optional):
                A list of finding status. acceptable values:
                `New`, `Active`, `Re-Opened`, `Fixed`
            severities (list(int), optional:
                A list of finding severities. Accetable values: `1`, `2`, `3`, `4`, `5`
            filter_superseded_qids (bool, optional):
                When false, includes all QIDs even if they’ve been superseded. When
                True filter out QIDs that have been superseded by another QID in
                the results.
            page_size (int, optional):
                How many records should be included in each page we download

        Docs:
            page 552
        """
        if not status:
            status = ['New', 'Active', 'Re-Opened', 'Fixed']
        if not severities:
            severities = [1, 2, 3, 4, 5]
        severities = [str(i) for i in severities]
        params = {
            'action': 'list',
            'show_asset_id': 1,
            #'detail': 'All', #option: {Basic|Basic/AGs|All|All/AGs | None}
            'show_qds': 1,
            'show_qds_factors': 1,
            'show_tags': 1,
            'host_metadata': 'all',  # List cloud and non-cloud
            'show_cloud_tags': 1,
            'include_vuln_type': 'confirmed',
            'show_reopened_info': 1,
            'include_ignored': int(include_ignored),
            'include_disabled': int(include_disabled),
            'status': ','.join(status),
            'severities': ','.join(severities),
            'compliance_enabled': int(compliance_enabled),
            'filter_superseded_qids': int(filter_superseded_qids),
            'truncation_limit': page_size,
        }

        if since is not None:
            params['detection_updated_since'] = arrow.get(since).isoformat()
        return xml_handler(self._api, self._path, params, Host, tag='HOST')

    def vuln(self, since: int | None = None, **kwargs) -> xml_handler:
        """
        Get all vuln findings

        Args:
            page_size (int): The page size we want to download
            since optional(Arrow:str):
                An arrow object or time string to pull data since. If None we pull
                api default.
        Returns:
            QualysIterator
        """

        return self._list(compliance_enabled=False, since=since, **kwargs)

    def compliance(self, since: int | None = None, **kwargs) -> xml_handler:
        """
        Get all compliance findings

        Args:
            page_size (int): The page size we want to download
            since optional(Arrow:str):
                An arrow object or time string to pull data since. If None we pull
                api default.
        Returns:
            QualysIterator
        """
        raise NotImplementedError('This feature hasnt been implemented yet')
        # return self._list(compliance_enabled=True,
        #                  since=since,
        #                  **kwargs
        #                  )
