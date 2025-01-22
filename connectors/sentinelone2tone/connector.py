#!/usr/bin/env python
import logging
from typing import Annotated

from pydantic import AnyHttpUrl, Field, SecretStr
from sentinelone.transform import Transformer
from tenint import Connector, Credential, Settings, TenableVMCredential


class SentinelOneCredential(Credential):
    """
    Sentinel One Credentials
    """

    prefix: str = "s1"
    name: str = "SentinelOne Singularity"
    slug: str = "s1"
    api_token: SecretStr
    url: AnyHttpUrl


class AppSettings(Settings):
    """
    SentinelOne2TOne Connector Settings
    """

    debug: Annotated[bool, Field(title="Debug")] = False
    import_findings: Annotated[bool, Field(title="Import Findings")] = True


connector = Connector(
    settings=AppSettings, credentials=[SentinelOneCredential, TenableVMCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    SentinelOne to Tenable One Connector
    """
    if config.debug:
        logging.getLogger().setLevel("DEBUG")
    transformer = Transformer()
    transformer.run(get_findings=config.import_findings)


if __name__ == "__main__":
    connector.app()
