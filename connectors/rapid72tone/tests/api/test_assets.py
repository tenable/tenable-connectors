import responses
from responses.matchers import query_param_matcher


@responses.activate
def test_assets_list(rsapi, asset_page_one):
    responses.get(
        url='https://10.50.12.188:3780/api/3/assets',
        match=[
            query_param_matcher(
                {'page': 0, 'size': 500, 'sort': 'id,asc'},
                strict_match=False,
            )
        ],
        json=asset_page_one,
    )

    resp = rsapi.assets.list()

    for item in resp:
        assert isinstance(item, dict)
