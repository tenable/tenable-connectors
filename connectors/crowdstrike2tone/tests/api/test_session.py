import pytest

from crowdstrike import CrowdStrikeAPI


def test_api_session_init_test_connection():
    with pytest.raises(ConnectionError, match='No valid url provided'):
        CrowdStrikeAPI()

    with pytest.raises(ConnectionError, match='No valid client_id provided'):
        CrowdStrikeAPI(url='https://nourl.crowdstrike')

    with pytest.raises(ConnectionError, match='No valid client_secret provided'):
        CrowdStrikeAPI(url='https://nourl.crowdstrike', client_id='something')


def test_api_session_envvars(monkeypatch, token_response):
    monkeypatch.setenv('CROWDSTRIKE_URL', 'https://nourl.crowdstrike')
    monkeypatch.setenv('CROWDSTRIKE_CLIENT_ID', 'something')
    monkeypatch.setenv('CROWDSTRIKE_CLIENT_SECRET', 'something')
    monkeypatch.setenv('CROWDSTRIKE_MEMBER_CID', 'something')
    m = CrowdStrikeAPI()

    assert m._url == 'https://nourl.crowdstrike'
    assert m.client_id == 'something'
    assert m.client_secret == 'something'
    assert m.member_cid == 'something'
