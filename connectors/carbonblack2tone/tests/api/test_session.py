import os
import pytest
from unittest.mock import patch
from carbonblack import CarbonBlackAPI

ENV_VARS = {
    'CARBON_BLACK_URL': 'https://nourl.carbonlack',
    'CARBON_BLACK_API_ID': 'test_api_id',
    'CARBON_BLACK_API_SECRET': 'test_api_secret',
    'CARBON_BLACK_ORG_KEY': 'test_org_key',
}


def test_api_session_init_test_connection():
    with pytest.raises(ConnectionError, match='No valid CARBON_BLACK_URL provided.'):
        CarbonBlackAPI()


def test_api_session_init_api_id_error():
    with pytest.raises(ConnectionError, match='No valid CARBON_BLACK_API_ID provided.'):
        CarbonBlackAPI(url='https://nourl.carbonlack')


def test_api_session_init_api_secret_error():
    with pytest.raises(
        ConnectionError, match='No valid CARBON_BLACK_API_SECRET provided.'
    ):
        CarbonBlackAPI(url='https://nourl.carbonlack', api_id='test_api_id')


def test_api_session_init_org_key_error():
    with pytest.raises(
        ConnectionError, match='No valid CARBON_BLACK_ORG_KEY provided.'
    ):
        CarbonBlackAPI(
            url='https://nourl.carbonlack',
            api_id='test_api_id',
            api_secret='test_api_secret',
        )


@patch.dict(os.environ, ENV_VARS)
def test_api_session_envvars():
    cb_obj = CarbonBlackAPI()

    assert cb_obj._url == ENV_VARS.get('CARBON_BLACK_URL')
    assert cb_obj.api_id == ENV_VARS.get('CARBON_BLACK_API_ID')
    assert cb_obj.api_secret == ENV_VARS.get('CARBON_BLACK_API_SECRET')
    assert cb_obj.org_key == ENV_VARS.get('CARBON_BLACK_ORG_KEY')


#
