import pytest
import responses
from responses.matchers import query_param_matcher


@responses.activate
def test_findings_list(qapi, findings_page):
    responses.get(
        'https://nourl.qualys/api/2.0/fo/asset/host/vm/detection/',
        body=findings_page,
        match=[
            query_param_matcher(
                {
                    'action': 'list',
                    'show_asset_id': 1,
                    'show_qds': 1,
                    'show_qds_factors': 1,
                    'show_tags': 1,
                    'host_metadata': 'all',
                    'show_cloud_tags': 1,
                    'include_vuln_type': 'confirmed',
                    'show_reopened_info': 1,
                    'include_ignored': 0,
                    'include_disabled': 0,
                    'status': 'New,Active,Re-Opened,Fixed',
                    'severities': '1,2,3,4,5',
                    'compliance_enabled': 0,
                    'filter_superseded_qids': 1,
                    'truncation_limit': 10000,
                }
            )
        ],
    )
    findings = qapi.findings._list()
    for finding in findings:
        assert isinstance(finding, dict)


@responses.activate
def test_findings_vuln(qapi, findings_page):
    responses.get(
        'https://nourl.qualys/api/2.0/fo/asset/host/vm/detection/',
        body=findings_page,
        match=[
            query_param_matcher(
                {
                    'action': 'list',
                    'show_asset_id': 1,
                    'show_qds': 1,
                    'show_qds_factors': 1,
                    'show_tags': 1,
                    'host_metadata': 'all',
                    'show_cloud_tags': 1,
                    'include_vuln_type': 'confirmed',
                    'show_reopened_info': 1,
                    'include_ignored': 0,
                    'include_disabled': 0,
                    'status': 'New,Active,Re-Opened,Fixed',
                    'severities': '1,2,3,4,5',
                    'compliance_enabled': 0,
                    'filter_superseded_qids': 1,
                    'truncation_limit': 10000,
                    'detection_updated_since': '2024-12-03T14:01:27+00:00',
                }
            )
        ],
    )
    findings = qapi.findings.vuln(since=1733234487)
    for finding in findings:
        assert isinstance(finding, dict)


def test_findings_compliance(qapi):
    with pytest.raises(NotImplementedError):
        qapi.findings.compliance()
