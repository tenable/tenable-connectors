from restfly.endpoint import APIEndpoint

from sentinelone.api.iterator import SentinelOneIterator


class Findings(APIEndpoint):
    _path = 'application-management/risks'

    def apps_w_risk(
        self,
        limit: int = 1000,
        **kwargs,
    ) -> SentinelOneIterator:
        """
        Get app ids with risk
        Step 1
        Required Permissions:
            Applications Page.viewRisks
        """
        _path = f'{self._path}/applications'

        params = {
            'limit': limit,
        }
        return SentinelOneIterator(
            self._api,
            _envelope='data',
            _path=_path,
            _params=params,
            _api_name='findings:apps_w_risk',
        )

    def cves_on_app(
        self,
        app_ids: list,
        limit: int = 1000,
        **kwargs,
    ) -> SentinelOneIterator:
        """
        get cves on an app
        """
        _path = f'{self._path}/cves'

        params = {
            'limit': limit,
            'applicationIds': app_ids,
        }
        return SentinelOneIterator(
            self._api,
            _envelope='data',
            _path=_path,
            _params=params,
            _api_name='findings:cves_on_app',
        )

    def endpoints_w_apps(
        self,
        app_ids: list,
        limit: int = 100,
        **kwargs,
    ) -> SentinelOneIterator:
        """
        get cves on assets
        """
        _path = f'{self._path}/endpoints'
        params = {
            'limit': limit,
            'applicationIds': app_ids,
        }
        return SentinelOneIterator(
            self._api,
            _envelope='data',
            _path=_path,
            _params=params,
            _api_name='findings:endpoints_w_apps',
        )
