import pytest
import responses
from responses.registries import OrderedRegistry
from restfly import APISession
from tenable.errors import APIError

from qualys.api.models.asset import Host
from qualys.api.streaming import handle_request, xml_handler


@pytest.fixture
def test_session():
    class TestSession(APISession):
        _url = 'https://nourl.com'

    return TestSession()


@responses.activate
def test_handle_request(test_session, asset_page):
    responses.get('https://nourl.com/', body=asset_page)

    h = handle_request(api=test_session, url='')
    assert h.content == bytes(asset_page, encoding='utf-8')


@responses.activate(registry=OrderedRegistry)
def test_handle_retry_counter(test_session, asset_page):
    responses.get('https://nourl.com/', status=400)
    responses.get('https://nourl.com/', status=400)
    responses.get('https://nourl.com/', body=asset_page)
    with pytest.raises(APIError):
        handle_request(api=test_session, url='', retries=0)

    h = handle_request(api=test_session, url='', delay=1)
    assert h.content == bytes(asset_page, encoding='utf-8')


@responses.activate(registry=OrderedRegistry)
def test_xml_handler(test_session, asset_page, asset_page_one):
    responses.get('https://nourl.com/', body=asset_page_one)
    responses.get('https://nourl.com/', body=asset_page)
    data = xml_handler(test_session, path='', params={}, model=Host, tag='HOST')
    for item in data:
        assert isinstance(item, dict)
