#!/usr/bin/env python

from typing import Annotated

from pydantic import AnyHttpUrl, Field, SecretStr
from tenint import Connector, Credential, Settings, TenableCloudCredential

from carbonblack.transform import Transformer


class CarbonBlackCredential(Credential):
    """
    Carbon Black Credentials
    """

    prefix: str = 'carbonblack'
    name: str = 'CarbonBlack'
    slug: str = 'CarbonBlack'
    description: str = 'Carbon Black API Credential'
    api_id: Annotated[
        str,
        Field(title='API ID', description='A Carbon Black API ID.'),
    ]
    api_secret: Annotated[
        SecretStr,
        Field(title='API Secret Key', description='A Carbon Black API Secret Key'),
    ]
    org_key: Annotated[
        str,
        Field(title='Organization Key', description='A Carbon Black Organization Key.'),
    ]
    url: Annotated[
        AnyHttpUrl,
        Field(
            title='Carbon Black Host URL', description='A valid Carbon Black site URL'
        ),
    ]


class AppSettings(Settings):
    """
    Carbon Black Connector Settings
    """

    import_findings: Annotated[
        bool,
        Field(
            title='Import Findings',
            description=(
                'Check Whether or Not To Import the Microsoft Defender '
                'Vulnerability Findings',
            ),
        ),
    ] = True


connector = Connector(
    settings=AppSettings, credentials=[CarbonBlackCredential, TenableCloudCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    Carbon Black to Tenable One Connector
    """
    transformer = Transformer()
    counts = transformer.run(
        import_findings=config.import_findings,
    )
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
