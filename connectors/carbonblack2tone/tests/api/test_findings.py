import responses


@responses.activate
def test_finding_list(
    cba,
    finding_details_response,
):
    responses.post(
        url='https://nourl.carbonlack/vulnerability/assessment/api/v1/orgs/test_org_key/devices/vulnerabilities/_search?vulnerabilityVisibility=ACTIVE',
        json=finding_details_response,
    )
    resp = cba.findings.list(page_size=1001)
    for item in resp:
        assert isinstance(item, dict)
