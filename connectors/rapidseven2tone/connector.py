#!/usr/bin/env python
from typing import Annotated

from pydantic import AnyHttpUrl, Field
from tenint import Connector, Credential, Settings, TenableCloudCredential

from rapidseven.transform import Transformer


class RapidSevenCredential(Credential):
    """
    RapidSeven Credentials
    """

    url: AnyHttpUrl
    username: str
    password: str
    description: str = 'RapidSeven API Credential'


class AppSettings(Settings):
    """
    RapidSeven Connector Settings
    """

    import_findings: Annotated[
        bool,
        Field(
            title='Import Findings',
            description=(
                'Check Whether or Not To Import the Rapid Seven Vulnerability Findings',
            ),
        ),
    ] = True


connector = Connector(
    settings=AppSettings, credentials=[RapidSevenCredential, TenableCloudCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    RapidSeven to Tenable One Connector
    """
    transformer = Transformer()
    counts = transformer.run(get_findings=config.import_findings)
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
