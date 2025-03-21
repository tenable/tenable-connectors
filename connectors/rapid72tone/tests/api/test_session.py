import pytest

from rapid7.api.session import Rapid7API


def test_api_session_init_test_connection(monkeypatch):
    monkeypatch.delenv('RAPID7_URL', raising=False)
    with pytest.raises(ConnectionError, match='No valid url provided'):
        Rapid7API()


def test_api_session_init_username_error(monkeypatch):
    monkeypatch.delenv('RAPID7_USERNAME', raising=False)
    with pytest.raises(ConnectionError, match='No valid username provided'):
        Rapid7API(url='something')


def test_api_session_init_password_error(monkeypatch):
    monkeypatch.delenv('RAPID7_PASSWORD', raising=False)
    with pytest.raises(ConnectionError, match='No valid password provided'):
        Rapid7API(url='something', username='something')


def test_api_session_envvars(monkeypatch):
    monkeypatch.setenv('RAPID7_URL', 'https://nourl.rapid7')
    monkeypatch.setenv('RAPID7_USERNAME', 'something')
    monkeypatch.setenv('RAPID7_PASSWORD', 'something')

    with Rapid7API() as m:
        assert m._url == 'https://nourl.rapid7'
        assert m.username == 'something'
        assert m.password == 'something'
        assert m._session.headers['Authorization'] is not None
