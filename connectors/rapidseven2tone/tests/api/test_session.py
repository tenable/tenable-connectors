import pytest

from rapidseven.api.session import RapidSevenAPI


def test_api_session_init_test_connection():
    with pytest.raises(ConnectionError, match='No valid url provided'):
        RapidSevenAPI()


def test_api_session_init_username_error():
    with pytest.raises(ConnectionError, match='No valid username provided'):
        RapidSevenAPI(url='something')


def test_api_session_init_password_error():
    with pytest.raises(ConnectionError, match='No valid password provided'):
        RapidSevenAPI(url='something', username='something')


def test_api_session_envvars(monkeypatch):
    monkeypatch.setenv('RAPIDSEVEN_URL', 'https://nourl.rapidseven')
    monkeypatch.setenv('RAPIDSEVEN_USERNAME', 'something')
    monkeypatch.setenv('RAPIDSEVEN_PASSWORD', 'something')

    with RapidSevenAPI() as m:
        assert m._url == 'https://nourl.rapidseven'
        assert m.username == 'something'
        assert m.password == 'something'
        assert m._session.headers['Authorization'] is not None
