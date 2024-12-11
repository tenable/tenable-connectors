import pytest
import responses
from responses.matchers import query_param_matcher


@responses.activate
def test_assets_list(qapi, asset_page):
    responses.get(
        'https://nourl.qualys/api/2.0/fo/asset/host/',
        match=[
            query_param_matcher(
                {
                    'action': 'list',
                    'show_asset_id': 1,
                    'show_ars': 1,
                    'show_tags': 1,
                    'show_ars_factors': 1,
                    'show_trurisk': 1,
                    'show_trurisk_factors': 1,
                    'show_cloud_tags': 1,
                    'truncation_limit': 10000,
                },
                strict_match=False,
            )
        ],
        body=asset_page,
    )
    resp = qapi.assets._list(compliance_enabled=False)
    for item in resp:
        assert isinstance(item, dict)


@responses.activate
def test_assets_vulns(qapi, asset_page):
    responses.get(
        'https://nourl.qualys/api/2.0/fo/asset/host/',
        match=[
            query_param_matcher(
                {
                    'action': 'list',
                    'show_asset_id': 1,
                    'show_ars': 1,
                    'show_tags': 1,
                    'show_ars_factors': 1,
                    'show_trurisk': 1,
                    'show_trurisk_factors': 1,
                    'show_cloud_tags': 1,
                    'truncation_limit': 10000,
                    'vm_scan_since': '2024-12-03T14:01:27+00:00',
                }
            )
        ],
        body=asset_page,
    )
    resp = qapi.assets.vuln(since=1733234487)
    for item in resp:
        assert isinstance(item, dict)


def test_assets_compliance(qapi):
    with pytest.raises(NotImplementedError):
        qapi.assets.compliance()
