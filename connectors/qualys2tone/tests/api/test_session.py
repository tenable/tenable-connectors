import pytest

from qualys.api import QualysAPI


def test_api_session_init_test_connection():
    with pytest.raises(ConnectionError, match='No valid API URL defined'):
        QualysAPI()


def test_api_session_init_user_and_pass_error():
    with pytest.raises(
        ConnectionError, match='username and/or password were not provided'
    ):
        QualysAPI(url='https://nourl.com')

    with pytest.raises(
        ConnectionError, match='username and/or password were not provided'
    ):
        QualysAPI(url='https://nourl.com', username='someone')

    with pytest.raises(
        ConnectionError, match='username and/or password were not provided'
    ):
        QualysAPI(url='https://nourl.com', password='secret')


def test_api_session_envvars(monkeypatch):
    monkeypatch.setenv('QUALYS_URL', 'https://nourl.com')
    monkeypatch.setenv('QUALYS_USERNAME', 'test_user')
    monkeypatch.setenv('QUALYS_PASSWORD', 'test_password')

    q = QualysAPI()
    assert q._url == 'https://nourl.com'
    assert q._session.auth == ('test_user', 'test_password')
    assert q._session.headers.get('X-Requested-With') == 'Qualys Ingester'
