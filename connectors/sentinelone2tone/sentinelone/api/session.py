import os
from restfly.session import APISession
from sentinelone.api.findings import Findings
from sentinelone.api.assets import Assets


class SentinelOneAPI(APISession):
    """

    Docs:
        https://usea1-partners.sentinelone.net/api-doc/overview
    """

    _base_path = 'web/api/v2.1'
    _box = True

    def __init__(self, **kwargs):
        """
        Initialize the SentinelOne API Session.

        Args:
            url: The customer API url
            api_token: The Customer instance URL
        """
        params = (
            ('url', os.environ.get('S1_URL')),
            ('api_token', os.environ.get('S1_API_TOKEN')),
        )
        for key, envval in params:
            if envval and not kwargs.get(key):
                kwargs[key] = envval
        if not kwargs.get('url'):
            raise ConnectionError('No valid url provided')
        if not kwargs.get('api_token'):
            raise ConnectionError('No valid api_token was not provided.')
        super().__init__(**kwargs)

    def _authenticate(self, api_token):
        self._session.headers = {
            'Authorization': f'ApiToken {api_token}',
            'Content-Type': 'application/json',
        }

    @property
    def assets(self):
        return Assets(self)

    @property
    def findings(self):
        return Findings(self)
