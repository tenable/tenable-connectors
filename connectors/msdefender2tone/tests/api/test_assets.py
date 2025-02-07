import arrow
import responses
from responses.matchers import query_param_matcher


@responses.activate
def test_assets_list(msdapi, asset_page):
    ts = arrow.get(0).format('YYYY-MM-DDTHH:mm:ss[Z]')
    responses.get(
        url='https://nourl.msdefender/api/v1.0/machines',
        match=[
            query_param_matcher(
                {'$skip': 0, '$top': 10000, '$filter': f'lastSeen ge {ts}'},
                strict_match=False,
            )
        ],
        json=asset_page,
    )
    resp = msdapi.assets.list(last_seen=0)
    for item in resp:
        assert isinstance(item, dict)
