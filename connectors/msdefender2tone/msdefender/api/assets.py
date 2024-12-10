from typing import Optional

import arrow
from restfly.endpoint import APIEndpoint

from .iterator import MsDefenderIterator


class AssetsAPI(APIEndpoint):
    _path = 'machines'

    def list(
        self,
        page_size: int = 10000,
        last_seen: Optional[int] = None,
        **kwargs,
    ) -> MsDefenderIterator:
        """
        Returns a list of machines

        Args:
                id: (int): The object id
                page_size (int, optional): Page size of the request
                last_seen (int, optional):

        Returns:
                MsDefenderIterator

        Required Permissions:
                Machine.Read.All

        `API Docs <https://learn.microsoft.com/en-us/defender-endpoint/api>`_
        """
        params = {}
        if last_seen is not None:
            ts = arrow.get(last_seen).format('YYYY-MM-DDTHH:mm:ss[Z]')
            params['filter'] = f'lastSeen ge {ts}'

        return MsDefenderIterator(
            self._api,
            _method='GET',
            _envelope='value',
            _path=self._path,
            _page_size=page_size,
            _params=params,
            _max_page_size=10000,
        )
