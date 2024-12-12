import pytest
from msdefender import MSDefenderAPI

def test_api_session_init_test_connection():
    with pytest.raises(ConnectionError, match='No valid tenant_id provided'):
        MSDefenderAPI()
            
def test_api_session_init_app_id_error():
    with pytest.raises(ConnectionError, match='No valid app_id provided.'):
        MSDefenderAPI(tenant_id='something')

def test_api_session_init_app_secret_error():
    with pytest.raises(ConnectionError, match='No valid app_secret provided.'):
        MSDefenderAPI(tenant_id='something', app_id='something')

#def test_api_session_envvars(monkeypatch):
#    monkeypatch.setenv('MS_DEFENDER_TENANT_ID', 'something')
#    monkeypatch.setenv('MS_DEFENDER_APP_ID', 'something')
#    monkeypatch.setenv('MS_DEFENDER_APP_SECRET', 'something')
#        
#    m = MSDefenderAPI(
#        _base_token_url='https://nourl.msdefender'
#    )
#    
#    assert m.tenant_id == 'something'
#    assert m.app_id == 'something'
#    assert m.app_secret == 'something'
#