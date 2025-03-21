import responses


@responses.activate
def test_assets_list(
    cba,
    asset_details_response,
):
    responses.post(
        url='https://nourl.carbonlack/appservices/v6/orgs/test_org_key/devices/_search',
        json=asset_details_response,
    )
    resp = cba.assets.list(page_size=10001)
    for item in resp:
        assert isinstance(item, dict)
