#!/usr/bin/env python
import logging
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
    api_token: SecretStr
    url: AnyHttpUrl


class AppSettings(Settings):
    """
    SentinelOne2TOne Connector Settings
    """

    debug: Annotated[bool, Field(title='Debug')] = False
    import_findings: Annotated[bool, Field(title='Import Findings')] = True


connector = Connector(
    settings=AppSettings, credentials=[SentinelOneCredential, TenableCloudCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    SentinelOne to Tenable One Connector
    """
    if config.debug:
        logging.getLogger().setLevel('DEBUG')
    transformer = Transformer()
    counts = transformer.run(get_findings=config.import_findings)
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
