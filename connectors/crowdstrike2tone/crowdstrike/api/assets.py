from typing import Dict, List, Optional, Union

import arrow
from box import Box, BoxList
from requests import Response
from restfly.endpoint import APIEndpoint
from restfly.errors import BadRequestError

from crowdstrike.api.iterator import CrowdstrikeAssetIterator


class AssetsAPI(APIEndpoint):
    def list(
        self,
        limit: int = 5000,
        sort: Optional[str] = 'last_seen.asc',
        last_seen_days: Optional[int] = 1,
        filter: Optional[str] | None = None,
        **kwargs,
    ) -> CrowdstrikeAssetIterator:
        """
        Get all hosts

        Args:
            limit (int):
                the number of items to return. This should never be more than 5000
                as the following api call to get details only accepts max 5000
            sort (str, optional): the FQL sort parameter
            last_seen_days (int, optional):
                the number of days back to search back if filter isn't provided.
            filter (str, optional):
                The filter string in FQL format to filter CS assets
        Returns:
            CrowdstrikeAssetIterator

        """
        _path = 'devices/queries/devices-scroll/v1'
        if limit > 5000:
            self._log.warning(
                f'limit must be <= 5000; {limit} provided. Setting to 5000.'
            )
            limit = 5000
        params = {
            'limit': limit,
            'sort': sort,
        }
        if filter:
            params['filter'] = filter
        else:
            last_seen = (
                arrow.utcnow()
                .shift(days=-last_seen_days)
                .format('YYYY-MM-DDTHH:mm:ssZ')
            )
            params['filter'] = (
                f"last_seen:>='{last_seen}'"  # +provision.status:['Provisioned']"
            )
        return CrowdstrikeAssetIterator(
            self._api,
            _envelope='resources',
            _path=_path,
            _params=params,
        )

    def _device_details(
        self, ids: List[str]
    ) -> Union[Box, BoxList, Response, Dict, List, None]:
        """
        Get all device details for the provided CS device ids
        Args:
            ids (list): list of device ids to get details from.
        """

        _path = 'devices/entities/devices/v2'

        if len(ids) > 5000:
            raise BadRequestError(
                f'{len(ids)} asset ids provided but only 5000 are supported.'
            )

        body = {'ids': ids}
        return self._post(_path, json=body)
