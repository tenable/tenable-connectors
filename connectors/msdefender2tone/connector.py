#!/usr/bin/env python
import logging
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
    tenant_id: str
    app_id: str
    app_secret: SecretStr


class AppSettings(Settings):
    """
    Microsoft Defender Connector Settings
    """

    debug: Annotated[bool, Field(title='Debug')] = False
    import_findings: Annotated[bool, Field(title='Import Findings')] = True


connector = Connector(
    settings=AppSettings, credentials=[MSDefenderCredential, TenableCloudCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    MS Defender to Tenable One Connector
    """
    if config.debug:
        logging.getLogger().setLevel('DEBUG')
    transformer = Transformer()
    counts = transformer.run(get_findings=config.import_findings)
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
