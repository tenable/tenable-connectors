from typing import Any, Dict

from restfly.iterator import APIIterator


class Rapid7Iterator(APIIterator):
    _path: str
    _params: Dict[str, Any]

    def _get_page(self):
        resp = self._api.get(self._path, params=self._params)

        # Set total items and total pages from 1st API call
        if self.total is None:
            self.total = resp.page.totalResources

        self.page = resp.resources
        self._params['page'] += 1
