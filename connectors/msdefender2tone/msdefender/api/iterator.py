from typing import Dict, Any
from restfly.iterator import APIIterator
from copy import copy


class MsDefenderIterator(APIIterator):
    _path: str
    _envelope: str
    _params: Dict[str, Any]
    _page_size: int
    _max_page_size: int = 10000
    num_pages: int

    def __init__(self, api, **kwargs):
        super().__init__(api, **kwargs)
        if self._page_size > self._max_page_size:
            self._log.warning(
                (
                    f'Requested page size of "{self._page_size} is '
                    'larger than the maximum page size of '
                    f'{self._max_page_size}.  Automatically '
                    f'reducing the page to {self._max_page_size}.'
                )
            )
            self._page_size = self._max_page_size

    def _get_page(self):
        params = copy(self._params)
        params['skip'] = self._page_size * self.num_pages
        params['top'] = self._page_size
        resp = self._api.get(self._path, params=params)
        self.page = resp[self._envelope]
