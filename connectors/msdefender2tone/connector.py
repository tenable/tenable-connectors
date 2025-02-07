#!/usr/bin/env python
from typing import Annotated

from pydantic import Field, SecretStr
from tenint import Connector, Credential, Settings, TenableCloudCredential

from msdefender.transform import Transformer


class MSDefenderCredential(Credential):
    """
    MS Defender Credentials
    """

    prefix: str = 'ms_defender'
    name: str = 'MS Defender'
    slug: str = 'ms_defender'
    description: str = 'Microsoft Defender Credential'
    tenant_id: Annotated[
        str, Field(title='Tenant Id', description='MS Defender Tenant Id')
    ]
    app_id: Annotated[str, Field(title='App Id', description='MS Defender App Id')]
    app_secret: Annotated[
        SecretStr, Field(title='App Secret', description='MS Defender App Secret')
    ]


class AppSettings(Settings):
    """
    Microsoft Defender Connector Settings
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
    settings=AppSettings, credentials=[MSDefenderCredential, TenableCloudCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    MS Defender to Tenable One Connector
    """
    transformer = Transformer()
    counts = transformer.run(get_findings=config.import_findings)
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
