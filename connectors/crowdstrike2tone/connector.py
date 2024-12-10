#!/usr/bin/env python
import logging
from typing import Annotated

from pydantic import AnyHttpUrl, Field
from tenint import Connector, Credential, Settings, TenableVMCredential

from crowdstrike.transform import Transformer


class CrowdstrikeCredential(Credential):
    """
    Crowdstrike Credentials
    """

    prefix: str = 'crowdstrike'
    name: str = 'Crowdstrike'
    slug: str = 'crowdstrike'
    description: str = 'Crowdstrike API Credential'
    client_id: str
    client_secret: str
    member_cid: str
    url: AnyHttpUrl


class AppSettings(Settings):
    """
    Crowdstrike Connector Settings
    """

    debug: Annotated[bool, Field(title='Debug')] = False
    last_seen_days: Annotated[
        int, Field(title='How many days back to get assets/findings')
    ] = 1
    import_findings: Annotated[bool, Field(title='Import Findings')] = False


connector = Connector(
    settings=AppSettings, credentials=[CrowdstrikeCredential, TenableVMCredential]
)


@connector.job
def main(config: AppSettings):
    """
    Crowdstrike to Tenable One Connector
    """
    if config.debug:
        logging.getLogger().setLevel('DEBUG')
    transformer = Transformer()
    transformer.run(
        get_findings=config.import_findings, last_seen_days=config.last_seen_days
    )


if __name__ == '__main__':
    connector.app()
