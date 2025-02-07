from restfly.endpoint import APIEndpoint
from sentinelone.api.iterator import SentinelOneIterator


class Assets(APIEndpoint):
    _path = 'agents'

    def list(
        self,
        limit: int = 1000,
        **kwargs,
    ) -> SentinelOneIterator:
        """

        Required Permissions:
            Endpoints.view

        """
        params = {
            'limit': limit,
        }

        return SentinelOneIterator(
            self._api,
            _envelope='data',
            _path=self._path,
            _params=params,
            _api_name='assets:list',
        )
