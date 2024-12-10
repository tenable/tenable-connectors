import responses
from responses.matchers import query_param_matcher


@responses.activate
def test_kbs_list(qapi, kbs_page):
    responses.get(
        'https://nourl.qualys/api/2.0/fo/knowledge_base/vuln/',
        body=kbs_page,
        match=[
            query_param_matcher(
                {
                    'action': 'list',
                    'details': 'All',
                    'show_disabled_flag': 1,
                    'last_modified_after': '1999-01-01',
                }
            )
        ],
    )
    kbs = qapi.knowledgebase.list()
    for kb in kbs:
        assert isinstance(kb, dict)
