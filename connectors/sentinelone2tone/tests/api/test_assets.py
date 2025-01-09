import responses
from responses.matchers import query_param_matcher


@responses.activate
def test_assets_list(s1api, agent_page):
    responses.get(
        'https://nourl.s1/web/api/v2.1/agents',
        match=[
            query_param_matcher(
                {
                    'limit': 1000,
                },
                strict_match=False,
            )
        ],
        json=agent_page,
    )
    resp = s1api.assets.list()
    for item in resp:
        assert isinstance(item, dict)
