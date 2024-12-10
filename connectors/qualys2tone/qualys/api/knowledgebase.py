"""
Knowledgebase/Plugin handling module for Qualys
"""

import arrow
from restfly.endpoint import APIEndpoint

from .models.knowledgebase import KnowledgebaseVuln
from .streaming import xml_handler


class KnowledgeBaseAPI(APIEndpoint):
    _path = 'knowledge_base/vuln/'

    def list(self, since: int | None = None) -> xml_handler:
        """
        Collects the list of KNowledgebase articles from Qualys.

        Args:
            since:
                Only collect KBs newer than this date.

        Returns:
            Generator
        """
        params = {
            'action': 'list',
            'details': 'All',
            'show_disabled_flag': 1,
            'last_modified_after': arrow.get(since).format('YYYY-MM-DD')
            if since
            else '1999-01-01',
        }
        return xml_handler(self._api, self._path, params, KnowledgebaseVuln, tag='VULN')
