"""
QualysAPI APISession module.
"""

import os

from restfly.session import APISession

from .assets import AssetsAPI
from .findings import FindingsAPI
from .knowledgebase import KnowledgeBaseAPI


class QualysAPI(APISession):
    """
    Qualys API wrapper
    """

    _base_path = 'api/2.0/fo'
    _box = True

    """
    Docs:
        https://cdn2.qualys.com/docs/qualys-api-vmpc-user-guide.pdf
        API URLS: https://www.qualys.com/platform-identification/

    """

    def __init__(self, **kwargs):
        """
        Initialized the Qualys API Session.

        Args:
            url: The Qualys customer API url
            username: Username to authenticate with
            password: Password to authenticate with
        """
        params = (
            ('url', os.environ.get('QUALYS_URL')),
            ('username', os.environ.get('QUALYS_USERNAME')),
            ('password', os.environ.get('QUALYS_PASSWORD')),
        )
        for key, envval in params:
            if envval and not kwargs.get(key):
                kwargs[key] = envval
        if not kwargs.get('url'):
            raise ConnectionError('No valid API URL defined')
        if not (kwargs.get('username') and kwargs.get('password')):
            raise ConnectionError('username and/or password were not provided.')
        super().__init__(**kwargs)

    def _authenticate(self, username: str, password: str) -> None:
        # Todo Change header in teh future
        self._session.headers.update({'X-Requested-With': 'Qualys Ingester'})
        self._session.auth = (username, password)

    @property
    def assets(self):
        return AssetsAPI(self)

    @property
    def findings(self):
        return FindingsAPI(self)

    @property
    def knowledgebase(self):
        return KnowledgeBaseAPI(self)
