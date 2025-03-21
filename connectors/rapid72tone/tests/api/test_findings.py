import responses
from responses.matchers import query_param_matcher


@responses.activate
def test_asset_findings_list(rsapi, vuln_page_one, asset_id):
    responses.get(
        url=f'https://10.50.12.188:3780/api/3/assets/{asset_id}/vulnerabilities',
        match=[
            query_param_matcher(
                {'page': 0, 'size': 10, 'sort': 'id,asc'},
                strict_match=False,
            )
        ],
        json=vuln_page_one,
    )

    resp = rsapi.findings.list_asset_findings(asset_id=asset_id)

    for item in resp.page:
        assert isinstance(item, dict)


@responses.activate
def test_findings_list(rsapi, vuln_info):
    responses.get(
        url='https://10.50.12.188:3780/api/3/vulnerabilities',
        match=[
            query_param_matcher(
                {'page': 0, 'size': 500, 'sort': 'id,asc'},
                strict_match=False,
            )
        ],
        json=vuln_info,
    )

    resp = rsapi.findings.list_findings()

    for item in resp.page:
        assert isinstance(item, dict)
