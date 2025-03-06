from copy import copy
from typing import Any, Dict

from restfly.iterator import APIIterator


class CrowdstrikeAssetIterator(APIIterator):
    _path: str
    _envelope: str
    _params: Dict[str, Any]
    _offset: str | None = None
    _total_assets: int | None = None

    def _get_page(self):
        params = copy(self._params)
        if self._offset:
            params['offset'] = self._offset
        # params['skip'] = self._page_size * self.num_pages
        # params['top'] = self._page_size
        resp = self._api.get(self._path, params=params)
        pagination = resp.get('meta').get('pagination')
        self._offset = pagination.get('offset', None)
        if self._total_assets is None:
            self._total_assets = pagination.get('total')
            self._log.info(f'Total assets reported by api: {self._total_assets}')
        device_ids = resp[self._envelope]
        if len(device_ids) == 0:
            raise StopIteration()
        resp = self._api.assets._device_details(ids=device_ids)
        self.page = resp[self._envelope]


class CrowdstrikeFindingIterator(APIIterator):
    """
    An iterator to handle pagination for finding endpoints
    """

    _path: str
    _envelope: str
    _params: Dict[str, Any]
    _after: str | None = None

    def _get_page(self):
        """
        Get the next page of findings
        """
        if self._after:
            self._params['after'] = self._after

        resp = self._api.get(self._path, params=self._params)
        pagination = resp.get('meta').get('pagination')
        self._after = pagination.get('after')
        if not self.total:
            # set max_items, which is the total number of findings
            self.total = pagination.get('total')
            self._log.info(f'Total findings reported by api: {self.max_items}')
        self.page = resp.get(self._envelope, [])
