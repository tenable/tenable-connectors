from restfly.endpoint import APIEndpoint

from .iterator import TrendMicroIterator


class AssetsAPI(APIEndpoint):
    _path = 'endpointSecurity/endpoints'

    def _list(
        self,
        **kwargs,
    ) -> TrendMicroIterator:
        """
        Returns a list of endpoints.

        Returns:
                TrendMicroIterator

        Required Permissions:
                Endpoint Inventory: View

        `API Docs <https://automation.trendmicro.com/xdr/api-v3>`_
        """
        # top: Number of records displayed on a page setting default to 1000.
        # Valid values: 10 50 100 200 500 1000

        return TrendMicroIterator(
            self._api,
            _path=self._path,
            _params= {'top': 1000},
        )
