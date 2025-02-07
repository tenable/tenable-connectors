from typing import Optional
import arrow
from restfly.endpoint import APIEndpoint
from .iterator import MsDefenderIterator


class FindingsAPI(APIEndpoint):
    _path = 'vulnerabilities'

    def definitions(
        self,
        updated_on: Optional[int] = None,
        page_size: Optional[int] = 10000,
    ) -> MsDefenderIterator:
        """
        Returns a list of vulnerability resource types.

        Args:
            updated_on (str, optional):
                Return resource types updates on or after the specified date.
            page_size (int, optional):
                Specify the page size to be returned.

        Returns:
            MsDefenderIterator:
                An iterable containing the vulnerability definitions.

        Required Permission:
            Vulnerability.Read.All

        `API Docs <https://learn.microsoft.com/en-us/graph/api/security-vulnerability-get>`_
        """
        params = {}
        if updated_on is not None:
            ts = arrow.get(updated_on).format('YYYY-MM-DDTHH:mm:ss[Z]')
            params['filter'] = f'updatedOn ge {ts}'

        return MsDefenderIterator(
            self._api,
            _method='GET',
            _envelope='value',
            _page_size=page_size,
            _path=self._path,
            _max_page_size=10000,
            _params=params,
        )

    def vulns(self, page_size: int = 10000) -> MsDefenderIterator:
        """
        Get all vulnerabilities by machine and software

        Args:
            page_size (int, optional): Specify the page size to be returned.

        Returns:
            MsDefenderIterator:
                An iterable containing the vulnerability findings.

        Required Permission:
            Vulnerability.Read.All

        `API Docs <https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities-by-machines>`_
        """
        return MsDefenderIterator(
            self._api,
            _method='GET',
            _envelope='value',
            _page_size=page_size,
            _path=f'{self._path}/machinesVulnerabilities',
            _max_page_size=10000,
            _params={},
        )
