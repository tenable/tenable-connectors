from typing import Any, Dict

from restfly.iterator import APIIterator


class TrendMicroIterator(APIIterator):
    _path: str
    _params: Dict[str, Any]
    _next_page_url: str | None = None


    def _get_page(self):
        if self._next_page_url:
            response = self._api.get(self._next_page_url).json()
        else:
            response = self._api.get(self._path, params=self._params).json()
            self.total = response.get('totalCount')
        
        self._next_page_url = response.get('nextLink')
        self.page = response.get('items', [])
