from rapid7.database import Knowledgebase, init_db


def test_knowledgebase_model():
    db = init_db('sqlite:///:memory:')
    kb = Knowledgebase(
        id=1, cves=['CVE-2024-0001', 'CVE-2024-0002'], severity='CRITICAL'
    )
    assert kb.id == 1
    assert kb.cves == ['CVE-2024-0001', 'CVE-2024-0002']
    assert kb.severity == 'CRITICAL'

    kb2 = Knowledgebase(id=2, severity='LOW')
    assert kb2.id == 2
    assert kb2.cves is None
    assert kb2.severity == 'LOW'

    with db.session() as session:
        session.add(kb2)
        session.commit()
        assert kb2.cves == []
