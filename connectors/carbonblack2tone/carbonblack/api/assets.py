from restfly.endpoint import APIEndpoint
from .iterator import CarbonBlackIterator

MAX_PAGE_SIZE = 10000


class AssetsAPI(APIEndpoint):
    _path: str | None = None

    def list(self, page_size: int = 1000) -> CarbonBlackIterator:
        """
        Get all devices

        Args:
            page_size (int):
                The number of items to return. This should never be more than 10000
                as the following api call to get details only accepts max 10000
        Returns:
            CarbonBlackIterator

        """
        _path = f'appservices/v6/orgs/{self._api.org_key}/devices/_search'
        # If  page size is greater than MAX_PAGE_SIZE then set it to MAX_PAGE_SIZE.
        if page_size > MAX_PAGE_SIZE:
            self._log.warning(
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
            _kind='assets',
        )
