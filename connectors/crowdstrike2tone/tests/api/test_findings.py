import arrow
import responses
from responses.matchers import query_param_matcher


@responses.activate
def test_findings_vulns_without_filter(csapi, finding_details_page, last_seen_days=1):
    last_seen = (
        arrow.utcnow().shift(days=-last_seen_days).format('YYYY-MM-DDTHH:mm:ssZ')
    )
    responses.get(
        url='https://nourl.crowdstrike/spotlight/combined/vulnerabilities/v1',
        match=[
            query_param_matcher(
                {
                    'limit': 5000,
                    'filter': f'updated_timestamp:>"{last_seen}"+status:["open","reopen"]',
                    'facet': 'cve',
                },
                strict_match=False,
            )
        ],
        json=finding_details_page,
    )
    resp = csapi.findings.vulns()
    for item in resp:
        assert isinstance(item, dict)


@responses.activate
def test_findings_vulns_with_filter(csapi, finding_details_page, last_seen_days=2):
    last_seen = (
        arrow.utcnow().shift(days=-last_seen_days).format('YYYY-MM-DDTHH:mm:ssZ')
    )
    responses.get(
        url='https://nourl.crowdstrike/spotlight/combined/vulnerabilities/v1',
        match=[
            query_param_matcher(
                {
                    'limit': 5000,
                    'filter': f'updated_timestamp:>"{last_seen}"+status:["open","reopen"]',
                    'facet': 'cve',
                },
                strict_match=False,
            )
        ],
        json=finding_details_page,
    )
    resp = csapi.findings.vulns(limit=6000, last_seen_days=last_seen_days)
    for item in resp:
        assert isinstance(item, dict)
