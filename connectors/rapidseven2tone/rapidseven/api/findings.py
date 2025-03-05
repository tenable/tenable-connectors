from typing import Optional

from restfly.endpoint import APIEndpoint

from rapidseven.api.iterator import RapidSevenIterator


class FindingsAPI(APIEndpoint):
    def list_asset_findings(
        self,
        asset_id: int,
        page_num: Optional[int] = 0,
        size: Optional[int] = 500,
        sort: Optional[str] = 'id,asc',
        **kwargs,
    ) -> RapidSevenIterator:
        """
        Get all vulnerabilities for a specific asset

        Docs: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getAssetVulnerabilities

        Args:
            asset_id (int): The ID of the asset to retrieve the vulnerabilities.
            page_num (int, optional): The index of the page to retrieve. Default is 0.
            size (int, optional): The number of records per page to retrieve. Default is 1000
            sort (str, optional): The criteria to sort the records by, in the format: property[,ASC|DESC].
                The default sort order is ascending.
                Multiple sort criteria can be specified using multiple sort query parameters.
        Returns:
            RapidSevenIterator
        """  # noqa: E501
        _path = f'api/3/assets/{asset_id}/vulnerabilities'

        params = {
            'page': page_num,
            'size': size,
            'sort': sort,
        }

        return RapidSevenIterator(
            self._api,
            _path=_path,
            _params=params,
        )

    def list_findings(
        self,
        page_num: Optional[int] = 0,
        size: Optional[int] = 500,
        sort: Optional[str] = 'id,asc',
        **kwargs,
    ) -> RapidSevenIterator:
        """
        Get all vulnerabilities that can be scanned by Rapid7

        Docs: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getVulnerabilities

        Args:
            page_num (int, optional): The index of the page to retrieve. Default is 0.
            size (int, optional): The number of records per page to retrieve. Default is 10
            sort (str, optional): The criteria to sort the records by, in the format: property[,ASC|DESC].
                The default sort order is ascending.
                Multiple sort criteria can be specified using multiple sort query parameters.
        Returns:
            RapidSevenIterator
        """  # noqa: E501
        _path = 'api/3/vulnerabilities'

        params = {
            'page': page_num,
            'size': size,
            'sort': sort,
        }

        return RapidSevenIterator(
            self._api,
            _path=_path,
            _params=params,
        )
