import responses
from responses.matchers import query_param_matcher

from trendmicro.api.assets import AssetsAPI
from trendmicro.api.iterator import TrendMicroIterator


@responses.activate
def test_assets(tmapi, asset_page):
    responses.get(
        'https://nourl.v1/v3.0/endpointSecurity/endpoints',
        match=[
            query_param_matcher(
                {'top': 1000},
                strict_match=False,
            )
        ],
        json=asset_page,
    )

    for item in tmapi.assets.list():
        assert item == asset_page['items'][0]

@responses.activate
def test_assets_list(tmapi, asset_page):
    assets_api = AssetsAPI(tmapi)

    responses.get(
        'https://nourl.v1/v3.0/endpointSecurity/endpoints',
        match=[
            query_param_matcher(
                {'top': 1000},
                strict_match=False,
            )
        ],
        json=asset_page,
    )

    iterator = assets_api._list()

    # Assertions to verify the list method works as expected
    assert isinstance(iterator, TrendMicroIterator)
    assert iterator._path == 'endpointSecurity/endpoints'
    assert iterator._params == {'top': 1000}
