import pytest

from sentinelone.api.session import SentinelOneAPI


def test_api_session_init_test_connection():
    with pytest.raises(ConnectionError, match='No valid url provided'):
        SentinelOneAPI()


def test_api_session_init_api_token_error():
    with pytest.raises(ConnectionError, match='No valid api_token was not provided.'):
        SentinelOneAPI(url='https://nourl.com')
