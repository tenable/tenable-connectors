#!/usr/bin/env python
import logging
from typing import Annotated

from crowdstrike.transform import Transformer
from pydantic import AnyHttpUrl, Field, SecretStr
from tenint import Connector, Credential, Settings, TenableVMCredential


class CrowdstrikeCredential(Credential):
    """
    Crowdstrike Credentials
    """

    prefix: str = "crowdstrike"
    name: str = "Crowdstrike"
    slug: str = "crowdstrike"
    description: str = "Crowdstrike API Credential"
    client_id: str
    client_secret: SecretStr
    member_cid: str | None = None
    url: AnyHttpUrl


class AppSettings(Settings):
    """
    Crowdstrike Connector Settings
    """

    debug: Annotated[bool, Field(title="Debug")] = False
    last_seen_days: Annotated[
        int, Field(title="How many days back to get assets/findings", ge=1, le=7)
    ] = 1
    import_findings: Annotated[bool, Field(title="Import Findings")] = False


connector = Connector(
    settings=AppSettings, credentials=[CrowdstrikeCredential, TenableVMCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    Crowdstrike to Tenable One Connector
    """
    if config.debug:
        logging.getLogger().setLevel("DEBUG")
    transformer = Transformer()
    transformer.run(
        get_findings=config.import_findings, last_seen_days=config.last_seen_days
    )


if __name__ == "__main__":
    connector.app()
