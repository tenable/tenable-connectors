from restfly.session import APISession
from .assets import AssetsAPI
from .findings import FindingsAPI
import os

class MSDefenderAPI(APISession):
    """
    Defender API package
    """
    _base_path = 'api/v1.0'
    _box = True
    _url = 'https://api.security.microsoft.com'
    _base_token_url = 'https://login.windows.net'
    
    def __init__(self, **kwargs):
        """
        Initialize the MSDefenderAPI API Session.
        
        Args:
            tenant_id: The customer Tenant ID
            api_token: The Customer instance URL
        """
        params = (
            ('tenant_id', os.environ.get('MS_DEFENDER_TENANT_ID')),
            ('app_id', os.environ.get('MS_DEFENDER_APP_ID')),
            ('app_secret', os.environ.get('MS_DEFENDER_APP_SECRET')),
        )
        for key, envval in params:
            if envval and not kwargs.get(key):
                kwargs[key] = envval
        if not kwargs.get('tenant_id'):
            raise ConnectionError('No valid tenant_id provided')
        if not kwargs.get('app_id'):
            raise ConnectionError('No valid app_id provided.')
        if not kwargs.get('app_secret'):
            raise ConnectionError('No valid app_secret provided.')
            
        self._base_token_url = kwargs.pop('_base_token_url', self._base_token_url)
        
        super().__init__(**kwargs)
    
    
    def _get_auth_token(
        self,
        tenant_id: str,
        app_id: str,
        app_secret: str,
        **kwargs,
    ) -> str:
        """
        
        """
        url = f'{self._base_token_url}/{tenant_id}/oauth2/token'
        body = {
            'resource' : 'https://api.securitycenter.windows.com',
            'client_id' : app_id,
            'client_secret' : app_secret,
            'grant_type' : 'client_credentials'
        }
        return self.post(url, data=body).access_token
      
          
    def _authenticate(
        self,
        tenant_id: str,
        app_id: str,
        app_secret: str,
        **kwargs,
    ) -> None:
        """
        Authentication Mechanism
        """

        token = self._get_auth_token(tenant_id, app_id, app_secret)
        self._session.headers = {
            'Content-Type' : 'application/json',
            'Authorization' : f'Bearer {token}'
        }

    def _req(self, method: str, path: str, **kwargs):
        """
        Overloads the query parameter handler to support non-standard query
        characters (OData uses $, spaces, and all kinds of nonsense).
        """
        params = kwargs.pop('params', {})
        if params:
            plist = [f'${k}={v}' for k, v in params.items()]
            path = f'{path}?{"&".join(plist)}'
        return super()._req(method, path, **kwargs)

    @property
    def assets(self):
        """
        Links to the Machine APIs.
        """
        return AssetsAPI(self)

    @property
    def findings(self):
        """
        Links to the Vuln APIs.
        """
        return FindingsAPI(self)
