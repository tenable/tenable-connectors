
import arrow
import responses
from responses.matchers import json_params_matcher, query_param_matcher

@responses.activate
def test_assets_list(csapi, asset_id_page, asset_details_page, last_seen_days=1):
    last_seen = arrow.utcnow().shift(days=-last_seen_days).format('YYYY-MM-DDTHH:mm:ssZ')
    responses.get(
        url='https://nourl.crowdstrike/devices/queries/devices-scroll/v1',
        match=[
            query_param_matcher(
                {
                    
                    'limit': 5000,
                    'sort': 'last_seen.asc',
                    'filter': f"last_seen:>='{last_seen}'"
                },
                strict_match=False,
            )
        ],
        json=asset_id_page,
    )
    responses.post(
        url='https://nourl.crowdstrike/devices/entities/devices/v2',
        json=asset_details_page,
    )
    resp = csapi.assets.list(limit=6000,last_seen_days=last_seen_days)
    for item in resp:
        assert isinstance(item, dict)

@responses.activate
def test_assets_device_details(csapi, asset_details_page):
    ids = ['11111111111']
    responses.post(
        url='https://nourl.crowdstrike/devices/entities/devices/v2',
        match = [
            json_params_matcher({'ids':ids})
        ],
        json=asset_details_page,
    )
    resp = csapi.assets._device_details(ids=ids)['resources']
    for item in resp:
        assert isinstance(item, dict)
    