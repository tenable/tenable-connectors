from restfly.endpoint import APIEndpoint
from .iterator import CarbonBlackIterator

MAX_PAGE_SIZE = 1000


class FindingsAPI(APIEndpoint):
    _path: str | None = None

    def list(self, page_size: int = 1000) -> CarbonBlackIterator:
        """
        Get all Active Vulnerabilities

        Args:
            page_size (int): the number of items to return. This should never be more than 1000
                as the following api call to get details only accepts max 1000
        Returns:
            CarbonBlackIterator

        """
        _path = f'vulnerability/assessment/api/v1/orgs/{self._api.org_key}/devices/vulnerabilities/_search?vulnerabilityVisibility=ACTIVE'

        # If  page size is greater than MAX_PAGE_SIZE then set it to MAX_PAGE_SIZE.
        if page_size > MAX_PAGE_SIZE:
            self._api._log.warning(
                f'page_size must be <= {MAX_PAGE_SIZE}; {page_size} provided. Setting to {MAX_PAGE_SIZE}.'
            )
            page_size = MAX_PAGE_SIZE

        params = {
            'start': 0,
            'rows': page_size,
        }
        return CarbonBlackIterator(
            self._api,
            _path=_path,
            _params=params,
            _kind='findings',
        )
