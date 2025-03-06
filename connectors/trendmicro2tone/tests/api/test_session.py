import pytest

from trendmicro.api.session import TrendMicroAPI


def test_api_session_envvars(monkeypatch):
    monkeypatch.setenv('TRENDMICRO_URL', 'https://nourl.com')
    monkeypatch.setenv('TRENDMICRO_TOKEN', 'test_token')

    tmapi = TrendMicroAPI()
    assert tmapi._url == 'https://nourl.com'
    assert tmapi._session.headers['Authorization'] == 'Bearer test_token'
    assert tmapi._session.headers['Content-Type'] == 'application/json;charset=utf-8'


def test_api_session_init_test_connection(monkeypatch):
    monkeypatch.delenv('TRENDMICRO_URL', raising=False)
    monkeypatch.delenv('TRENDMICRO_TOKEN', raising=False)

    with pytest.raises(ConnectionError, match='No valid url provided.'):
        TrendMicroAPI()


def test_api_session_init_token_error(monkeypatch):
    monkeypatch.delenv('TRENDMICRO_URL', raising=False)
    monkeypatch.delenv('TRENDMICRO_TOKEN', raising=False)

    with pytest.raises(ConnectionError, match='No valid token provided.'):
        TrendMicroAPI(url='something')
