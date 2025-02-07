#!/usr/bin/env python
from typing import Annotated

from pydantic import AnyHttpUrl, Field, SecretStr
from tenint import Connector, Credential, Settings, TenableCloudCredential

from crowdstrike.transform import Transformer


class CrowdstrikeCredential(Credential):
    """
    Crowdstrike Credentials
    """

    prefix: str = 'crowdstrike'
    name: str = 'Crowdstrike'
    slug: str = 'crowdstrike'
    description: str = 'Crowdstrike API Credential'
    client_id: Annotated[
        str,
        Field(
            title='Client Id',
            description='The API client id to authenticate your API requests.',
        ),
    ]
    client_secret: Annotated[
        SecretStr,
        Field(
            title='CrowdStrike Client Secret',
            description='The API client secret to authenticate your API requests.',
        ),
    ]
    member_cid: Annotated[
        str | None,
        Field(
            title='Member Customer ID',
            description=(
                'For MSSP Master CIDs, optionally lock the token to act on '
                'behalf of this member CID.'
            ),
        ),
    ] = None
    url: Annotated[
        AnyHttpUrl,
        Field(title='CrowdStrike Site URL', description='A valid CrowdStrike site URL'),
    ]


class AppSettings(Settings):
    """
    Crowdstrike Connector Settings
    """

    last_seen_days: Annotated[
        int, Field(description='How many days back to get assets/findings', ge=1, le=7)
    ] = 1


connector = Connector(
    settings=AppSettings, credentials=[CrowdstrikeCredential, TenableCloudCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    Crowdstrike to Tenable One Connector
    """
    transformer = Transformer()
    counts = transformer.run(get_findings=False, last_seen_days=config.last_seen_days)
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
