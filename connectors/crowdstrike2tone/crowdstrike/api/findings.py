from typing import Literal, Optional

import arrow
from restfly.endpoint import APIEndpoint

from .iterator import CrowdstrikeFindingIterator


class FindingsAPI(APIEndpoint):
    """
    The Findings API provides the ability to interact with the CrowdStrike Falcon
    Spotlight API. This API provides the ability to retrieve a list of vulnerabilities,
    sort and filter the results by specified criteria.
    """

    _path = 'spotlight/combined/vulnerabilities/v1'

    def vulns(
        self,
        limit: int = 5000,
        sort: Optional[Literal['updated_timestamp|asc', 'closed_timestamp|asc']] = None,
        last_seen_days: Optional[int] = 1,
    ) -> CrowdstrikeFindingIterator:
        """
        Retrieves a list of vulnerabilities.

        Args:
            limit:
                The maximum number of items to return. Defaults to 100, maximum of 5000.
            sort:
                The sort parameter, either ``updated_timestamp|asc`` or ``closed_timestamp|asc``.
                Defaults to ``None``.
            filter:
                The filter string in FQL format to filter CS findings with.
                Defaults to ``None``.
            facet:
                The list of fields to facet the results by. Defaults to ``None``.

        Returns:
            CrowdstrikeFindingIterator
        """
        status_filter = 'status:["open","reopen"]'

        if limit > 5000:
            self._log.warning(
                f'limit must be <= 5000; {limit} provided. Setting to 5000.'
            )
            limit = 5000
        params = {'limit': limit, 'sort': sort, 'facet': 'cve'}

        last_seen = (
            arrow.utcnow().shift(days=-last_seen_days).format('YYYY-MM-DDTHH:mm:ssZ')
        )
        params['filter'] = f'updated_timestamp:>"{last_seen}"+{status_filter}'
        return CrowdstrikeFindingIterator(
            self._api, _envelope='resources', _path=self._path, _params=params
        )
