from typing import Optional

from restfly.endpoint import APIEndpoint

from rapid7.api.iterator import Rapid7Iterator


class AssetsAPI(APIEndpoint):
    def list(
        self,
        page_num: Optional[int] = 0,
        size: Optional[int] = 500,
        sort: Optional[str] = 'id,asc',
        **kwargs,
    ) -> Rapid7Iterator:
        """
        Get all hosts

        Docs: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssets

        Args:
            page_num (int, optional): The index of the page to retrieve. Default is 0.
            size (int, optional): The number of records per page to retrieve. Default is 10
            sort (str, optional): The criteria to sort the records by, in the format: property[,ASC|DESC].
                The default sort order is ascending.
                Multiple sort criteria can be specified using multiple sort query parameters.
        Returns:
            Rapid7Iterator
        """  # noqa: E501
        _path = 'api/3/assets'

        params = {
            'page': page_num,
            'size': size,
            'sort': sort,
        }

        return Rapid7Iterator(
            self._api,
            _path=_path,
            _params=params,
        )
