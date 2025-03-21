#!/usr/bin/env python
from typing import Annotated

from pydantic import AnyHttpUrl, Field, SecretStr
from tenint import Connector, Credential, Settings, TenableCloudCredential

from qualys.transform import Transformer


class QualysCredential(Credential):
    """
    Qualys Credentials
    """

    prefix: str = 'qualys'
    name: str = 'Qualys VM'
    slug: str = 'qualys'
    description: str = 'Qualys QVM Credential'
    username: Annotated[
        str,
        Field(title='Account Username', description='Qualys API Account Username'),
    ]
    password: Annotated[
        SecretStr,
        Field(title='Account Password', description='Qualys API Account Password'),
    ]
    url: Annotated[
        AnyHttpUrl,
        Field(title='Account URL', description='Valid Qualys Site URL'),
    ]


class AppSettings(Settings):
    """
    Qualys2TOne Connector Settings
    """

    import_findings: Annotated[
        bool,
        Field(
            title='Import Findings',
            description=(
                'Check Whether or Not To Import the Qualys Vulnerability Findings'
            ),
        ),
    ] = True


connector = Connector(
    settings=AppSettings,
    credentials=[QualysCredential, TenableCloudCredential],
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    Qualys to Tenable One Connector
    """
    transformer = Transformer()
    counts = transformer.run(get_findings=config.import_findings)
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
