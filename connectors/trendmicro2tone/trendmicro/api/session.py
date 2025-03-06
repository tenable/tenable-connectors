import os

from restfly.session import APISession

from .assets import AssetsAPI


class TrendMicroAPI(APISession):
    """
    Trend Micro API package
    """

    _base_path = 'v3.0'

    def __init__(self, **kwargs):
        """
        Initialize the Trend Micro API Session.

        Args:
            url: The domain name for the region.
            token: The authentication token.
        """
        params = (
            ('url', os.environ.get('TRENDMICRO_URL')),
            ('token', os.environ.get('TRENDMICRO_TOKEN')),
        )
        for key, envval in params:
            if envval and not kwargs.get(key):
                kwargs[key] = envval
        if not kwargs.get('url'):
            raise ConnectionError('No valid url provided.')
        if not kwargs.get('token'):
            raise ConnectionError('No valid token provided.')

        super().__init__(**kwargs)

    def _authenticate(self, token: str) -> None:
        """
        Authentication for the Trend Micro API
        """
        self._session.headers = {
            'Content-Type': 'application/json;charset=utf-8',
            'Authorization': f'Bearer {token}',
        }

    @property
    def assets(self):
        """
        Links to the Endpoints API.
        """
        return AssetsAPI(self)
