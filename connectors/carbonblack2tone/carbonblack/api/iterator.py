from typing import Dict, Any
from restfly.iterator import APIIterator


class CarbonBlackIterator(APIIterator):
    _path: str
    _envelope: str = 'results'
    _params: Dict[str, Any]
    _kind: str

    def _get_page(self):
        """Overriding the _get_page function to get the data using carbon black api."""

        self._log.debug(
            f'Request to get {self._kind} using api: {self._path}, params: {self._params}'
        )
        resp = self._api.post(self._path, json=self._params)
        json_resp = resp.json()
        self.page = json_resp[self._envelope]
        if not self.total:
            self.total = json_resp['num_found']
        self._params['start'] += len(self.page)
