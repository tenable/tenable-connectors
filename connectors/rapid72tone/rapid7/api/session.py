import base64
import os

from pydantic import AnyHttpUrl
from restfly.session import APISession

from .assets import AssetsAPI
from .findings import FindingsAPI


class Rapid7API(APISession):
    _box = True
    username: str | None = None
    password: str | None = None
    url: AnyHttpUrl | None = None

    """
    Docs:
        https://help.rapid7.com/insightvm/en-us/api/index.html#section/Overview
    """

    def __init__(self, **kwargs):
        params = (
            ('url', os.environ.get('RAPID7_URL')),
            ('username', os.environ.get('RAPID7_USERNAME')),
            ('password', os.environ.get('RAPID7_PASSWORD')),
        )
        for key, envval in params:
            if envval and not kwargs.get(key):
                kwargs[key] = envval
        if not kwargs.get('url'):
            raise ConnectionError('No valid url provided')
        if not kwargs.get('username'):
            raise ConnectionError('No valid username provided')
        if not kwargs.get('password'):
            raise ConnectionError('No valid password provided')

        super().__init__(**kwargs)

    def _authenticate(self, **kwargs) -> None:
        """
        Authenticates to the Rapid7 API by setting the Authorization header to
        a base64 encoded string of the username and password.
        """
        if not self.username:
            self.username = kwargs.get('username')
        if not self.password:
            self.password = kwargs.get('password')

        # Encode username and password to base64
        credentials = f'{self.username}:{self.password}'
        token = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')

        self._session.headers.update({'Authorization': f'Basic {token}'})

    @property
    def assets(self) -> AssetsAPI:
        """
        Property that returns an instance of the AssetsAPI class, which is used to
        interact with the asset related endpoints.
        """
        return AssetsAPI(self)

    @property
    def findings(self) -> FindingsAPI:
        """
        Property that returns an instance of the FindingsAPI class, which is used to
        interact with the finding related endpoints.
        """
        return FindingsAPI(self)
