import arrow
import responses
from responses.matchers import query_param_matcher

@responses.activate
def test_findings_definitions(msdapi, definition_page):
    ts = arrow.get(0).format('YYYY-MM-DDTHH:mm:ss[Z]')
    responses.get(
        url='https://nourl.msdefender/api/v1.0/vulnerabilities',
        match=[
            query_param_matcher(
                {
                    
                    '$skip': 0,
                    '$top': 10000,
                    '$filter': f'updatedOn ge {ts}'
                },
                strict_match=False,
            )
        ],
        json=definition_page,
    )
    resp = msdapi.findings.definitions(updated_on=0)
    for item in resp:
        assert isinstance(item, dict)
        
@responses.activate
def test_findings_vulns(msdapi, vuln_page):
    
    responses.get(
        url='https://nourl.msdefender/api/v1.0/vulnerabilities/machinesVulnerabilities',
        match=[
            query_param_matcher(
                {
                    
                    '$skip': 0,
                    '$top': 10000,
                    
                },
                strict_match=False,
            )
        ],
        json=vuln_page,
    )
    resp = msdapi.findings.vulns()
    for item in resp:
        assert isinstance(item, dict)
        

