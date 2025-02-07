#!/usr/bin/env python
from typing import Annotated

from pydantic import AnyHttpUrl, Field, SecretStr
from tenint import Connector, Credential, Settings, TenableCloudCredential

from sentinelone.transform import Transformer


class SentinelOneCredential(Credential):
    """
    Sentinel One Credentials
    """

    prefix: str = 's1'
    name: str = 'SentinelOne Singularity'
    slug: str = 's1'
    api_token: Annotated[
        SecretStr, Field(title='API Token', description='SentinelOne API Token')
    ]
    url: Annotated[AnyHttpUrl, Field(title='URL', description='SentinelOne Site URL')]


class AppSettings(Settings):
    """
    SentinelOne2TOne Connector Settings
    """

    import_findings: Annotated[
        bool,
        Field(
            title='Import Findings',
            description=(
                'Check Whether or Not To Import the SenitinelOne Vulnerability Findings'
            ),
        ),
    ] = True


connector = Connector(
    settings=AppSettings, credentials=[SentinelOneCredential, TenableCloudCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    SentinelOne to Tenable One Connector
    """
    transformer = Transformer()
    counts = transformer.run(get_findings=config.import_findings)
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
