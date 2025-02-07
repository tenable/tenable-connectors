from restfly.session import APISession
from typing import Union, Dict, List
from requests import Response
from box import Box, BoxList

from .assets import AssetsAPI
from .findings import FindingsAPI

import os
import arrow


class CrowdStrikeAPI(APISession):
    _box = True
    token_expires_at: int | None = None
    client_id: str | None = None
    client_secret: str | None = None
    member_cid: str | None = None
    url: str | None = None

    """
    Docs:
        https://assets.falcon.us-2.crowdstrike.com/support/api/swagger-us2.html
    
    """

    def __init__(self, **kwargs):
        params = (
            ('url', os.environ.get('CROWDSTRIKE_URL')),
            ('client_id', os.environ.get('CROWDSTRIKE_CLIENT_ID')),
            ('client_secret', os.environ.get('CROWDSTRIKE_CLIENT_SECRET')),
            ('member_cid', os.environ.get('CROWDSTRIKE_MEMBER_CID')),
        )
        for key, envval in params:
            if envval and not kwargs.get(key):
                kwargs[key] = envval
        if not kwargs.get('url'):
            raise ConnectionError('No valid url provided')
        if not kwargs.get('client_id'):
            raise ConnectionError('No valid client_id provided')
        if not kwargs.get('client_secret'):
            raise ConnectionError('No valid client_secret provided')

        super().__init__(**kwargs)

    def _authenticate(self, **kwargs) -> None:
        if not self.client_id:
            self.client_id = kwargs.get('client_id')
        if not self.client_secret:
            self.client_secret = kwargs.get('client_secret')
        if not self.member_cid:
            self.member_cid = kwargs.get('member_cid')
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }
        if self.member_cid is not None:
            data['member_cid'] = self.member_cid
        ret = self.post('oauth2/token', data=data)
        self.token_expires_at = (
            arrow.utcnow()
            .shift(
                seconds=int(
                    ret.get('expires_in', 1799)
                    - 10  # reduce by 10 seconds just to be safe
                )
            )
            .int_timestamp
        )
        self._session.headers.update(
            {'Authorization': 'Bearer {}'.format(ret.get('access_token'))}
        )

    def _req(
        self, method: str, path: str, **kwargs
    ) -> Union[Box, BoxList, Response, Dict, List, None]:
        """
        Overload default request function to ensure we update our token before it expires
        """
        if (
            self.token_expires_at
            and arrow.utcnow().int_timestamp >= self.token_expires_at
        ):
            self.token_expires_at = None
            self._authenticate()

        return super()._req(method, path, **kwargs)

    @property
    def assets(self):
        return AssetsAPI(self)

    @property
    def findings(self):
        return FindingsAPI(self)


#
