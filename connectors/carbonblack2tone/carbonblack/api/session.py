import os
from .assets import AssetsAPI
from .findings import FindingsAPI
from restfly.session import APISession


class CarbonBlackAPI(APISession):
    """Class to create API session with Carbon black Server.
    Docs: https://developer.carbonblack.com/reference/carbon-black-cloud/authentication
    """

    api_id: str | None = None
    api_secret: str | None = None
    org_key: str | None = None
    url: str | None = None

    def __init__(self, **kwargs):
        params = (
            ('url', os.environ.get('CARBON_BLACK_URL')),
            ('api_id', os.environ.get('CARBON_BLACK_API_ID')),
            ('api_secret', os.environ.get('CARBON_BLACK_API_SECRET')),
            ('org_key', os.environ.get('CARBON_BLACK_ORG_KEY')),
        )

        for key, envval in params:
            if envval and not kwargs.get(key):
                kwargs[key] = envval
        if not kwargs.get('url'):
            raise ConnectionError('No valid CARBON_BLACK_URL provided.')
        if not kwargs.get('api_id'):
            raise ConnectionError('No valid CARBON_BLACK_API_ID provided.')
        if not kwargs.get('api_secret'):
            raise ConnectionError('No valid CARBON_BLACK_API_SECRET provided.')
        if not kwargs.get('org_key'):
            raise ConnectionError('No valid CARBON_BLACK_ORG_KEY provided.')

        super().__init__(**kwargs)

    def _authenticate(self, **kwargs) -> None:
        if not self.api_id:
            self.api_id = kwargs.get('api_id')
        if not self.api_secret:
            self.api_secret = kwargs.get('api_secret')
        if not self.org_key:
            self.org_key = kwargs.get('org_key')

        self._session.headers.update(
            {
                'X-AUTH-TOKEN': f'{self.api_secret}/{self.api_id}',
                'Content-Type': 'application/json',
            }
        )

    @property
    def assets(self):
        return AssetsAPI(self)

    @property
    def findings(self):
        return FindingsAPI(self)
