base = 'application-management/risks'

import responses
from responses.matchers import query_param_matcher


@responses.activate
def test_findings_apps_with_risk(s1api, app_page):
    responses.get(
        'https://nourl.s1/web/api/v2.1/application-management/risks/applications',
        match=[
            query_param_matcher(
                {
                    'limit': 1000,
                },
                strict_match=False,
            )
        ],
        json=app_page,
    )
    resp = s1api.findings.apps_w_risk()
    for item in resp:
        assert isinstance(item, dict)


@responses.activate
def test_findings_cves_on_app(s1api, cve_page, app_id):
    responses.get(
        'https://nourl.s1/web/api/v2.1/application-management/risks/cves',
        match=[
            query_param_matcher(
                {
                    'limit': 1000,
                    'applicationIds': app_id,
                },
                strict_match=False,
            )
        ],
        json=cve_page,
    )
    resp = s1api.findings.cves_on_app([app_id])
    for item in resp:
        assert isinstance(item, dict)


@responses.activate
def test_findings_endpoints_w_apps(s1api, endpoint_page, app_id):
    responses.get(
        'https://nourl.s1/web/api/v2.1/application-management/risks/endpoints',
        match=[
            query_param_matcher(
                {
                    'limit': 100,
                    'applicationIds': app_id,
                },
                strict_match=False,
            )
        ],
        json=endpoint_page,
    )
    resp = s1api.findings.endpoints_w_apps([app_id])
    for item in resp:
        assert isinstance(item, dict)
