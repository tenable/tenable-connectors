#!/usr/bin/env python
import logging
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
    username: str
    password: SecretStr
    url: AnyHttpUrl


class AppSettings(Settings):
    """
    Qualys2TOne Connector Settings
    """

    debug: Annotated[bool, Field(title='Debug')] = False
    import_findings: Annotated[bool, Field(title='Import Findings')] = True


connector = Connector(
    settings=AppSettings, credentials=[QualysCredential, TenableCloudCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    Qualys to Tenable One Connector
    """
    if config.debug:
        logging.getLogger().setLevel('DEBUG')
    transformer = Transformer()
    counts = transformer.run(get_findings=config.import_findings)
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
