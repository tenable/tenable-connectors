#!/usr/bin/env python
from typing import Annotated, Literal

from pydantic import AnyHttpUrl, Field, SecretStr
from tenint import Connector, Credential, Settings, TenableCloudCredential

from rapid7.transform import Transformer


class Rapid7Credential(Credential):
    """
    Rapid7 Credentials
    """

    prefix: Literal['rapid7'] = 'rapid7'
    name: Literal['Rapid7'] = 'Rapid7'
    slug: Literal['rapid7'] = 'rapid7'
    url: Annotated[
        AnyHttpUrl,
        Field(title='Rapid7 Site URL', description='A valid Rapid7 site URL'),
    ]
    username: Annotated[
        str,
        Field(title='Account Username', description='Rapid 7 Account Username'),
    ]
    password: Annotated[
        SecretStr,
        Field(title='Account Password', description='Rapid 7 Account Password'),
    ]
    description: str = 'Rapid7 Credentials'


class AppSettings(Settings):
    """
    Rapid7 Connector Settings
    """

    import_findings: Annotated[
        bool,
        Field(
            title='Import Findings',
            description=(
                'Check Whether or Not To Import the Rapid 7 Vulnerability Findings',
            ),
        ),
    ] = True


connector = Connector(
    settings=AppSettings, credentials=[Rapid7Credential, TenableCloudCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    Rapid7 to Tenable One Connector
    """
    transformer = Transformer()
    counts = transformer.run(get_findings=config.import_findings)
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
