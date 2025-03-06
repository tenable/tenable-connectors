from trendmicro.api.iterator import TrendMicroIterator


def test_trendmicro_iterator():
    iterator = TrendMicroIterator(None)
    assert iterator._next_page_url is None


def test_trendmicro_iterator_get_page(tmapi, asset_page):
    tmapi.get.return_value.json.return_value = asset_page

    iterator = TrendMicroIterator(
        tmapi, _path='endpointSecurity/endpoints', _params={'top': 10}
    )
    iterator._get_page()
    assert iterator._next_page_url is None


def test_trendmicro_iterator_get_page_with_next_link(tmapi, asset_page):
    next_link = (
        'https://nourl.v1/v3.0/endpointSecurity/endpoints?token=test_token&top=10'
    )
    asset_page['nextLink'] = next_link
    tmapi.get.return_value.json.return_value = asset_page

    iterator = TrendMicroIterator(
        tmapi,
        _path='endpointSecurity/endpoints?token=test_token&top=10',
        _params={'top': 10},
    )
    iterator._get_page()
    iterator._get_page()
    assert iterator._next_page_url == next_link
    assert iterator.page == asset_page['items']
