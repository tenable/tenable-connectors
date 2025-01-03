from copy import copy
from typing import Any, Dict

from restfly.iterator import APIIterator


class SentinelOneIterator(APIIterator):
    _path: str
    _envelope: str
    _params: Dict[str, Any]
    _api_name: str
    _cursor: str | None = None
    _total_assets: int | None = None

    def _get_page(self):
        params = copy(self._params)
        if self._cursor:
            params['cursor'] = self._cursor
        resp = self._api.get(self._path, params=params)
        pagination = resp.get('pagination')
        self._cursor = pagination.get('nextCursor', None)
        if self._total_assets is None:
            self._total_assets = pagination.get('totalItems')
            self.total = self._total_assets
            self._log.debug(
                f'Total records reported by {self._api_name} api: {self._total_assets}'
            )
        self.page = resp[self._envelope]


class SentinelOneFindings(APIIterator):
    current_app: dict
    current_cves: dict
