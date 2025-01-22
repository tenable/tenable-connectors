#!/usr/bin/env python
import logging
from typing import Annotated

from msdefender.transform import Transformer
from pydantic import Field, SecretStr
from tenint import Connector, Credential, Settings, TenableVMCredential


class MSDefenderCredential(Credential):
    """
    MS Defender Credentials
    """

    prefix: str = "ms_defender"
    name: str = "MS Defender"
    slug: str = "ms_defender"
    description: str = "Microsoft Defender Credential"
    tenant_id: str
    app_id: str
    app_secret: SecretStr


class AppSettings(Settings):
    """
    Microsoft Defender Connector Settings
    """

    debug: Annotated[bool, Field(title="Debug")] = False
    import_findings: Annotated[bool, Field(title="Import Findings")] = True


connector = Connector(
    settings=AppSettings, credentials=[MSDefenderCredential, TenableVMCredential]
)


@connector.job
def main(config: AppSettings, since: int | None = None):
    """
    MS Defender to Tenable One Connector
    """
    if config.debug:
        logging.getLogger().setLevel("DEBUG")
    transformer = Transformer()
    transformer.run(get_findings=config.import_findings)


if __name__ == "__main__":
    connector.app()
