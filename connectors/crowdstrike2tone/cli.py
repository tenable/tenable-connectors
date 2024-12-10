#!/usr/bin/env python3

from crowdstrike import CrowdStrikeAPI
from crowdstrike.transform import Transformer

import logging
from enum import Enum

from rich.logging import RichHandler
from tenable.io import TenableIO
from typer import Option, Typer
from typing_extensions import Annotated

app = Typer()

class LogLevels(str, Enum):
    debug = 'DEBUG'
    info = 'INFO'
    warn = 'WARN'
    error = 'ERROR'


def setup_logging(log_level: LogLevels) -> None:
    """
    Setup logging for qualys integration
    """
    fileHandler = logging.FileHandler('crowdstrike2tone.log')
    fileHandler.setFormatter(
        logging.Formatter(
            fmt='%(asctime)s %(levelname)-5.5s  %(message)s', datefmt='[%X]'
        )
    )
    logging.basicConfig(
        level=log_level.value,
        format='%(message)s',
        datefmt='[%X]',
        handlers=[RichHandler(rich_tracebacks=True), fileHandler],
    )
    
@app.command()
def run(
    tio_access_key: Annotated[
        str, Option(envvar='TIO_ACCESS_KEY', prompt=True, help='TVM/TIO API Access Key')
    ],
    tio_secret_key: Annotated[
        str, Option(envvar='TIO_SECRET_KEY', prompt=True, help='TVM/TIO API Secret Key')
    ],
    crowdstrike_url: Annotated[
        str, Option(envvar='CROWDSTRIKE_URL', prompt=True, help='Crowdstrike api url')
    ],
    crowdstrike_client_id: Annotated[
        str, Option(envvar='CROWDSTRIKE_CLIENT_ID', 
            prompt=True,
            help='The API client ID to authenticate your API requests.\n' 
                'https://falcon.crowdstrike.com/support/documentation/1/crowdstrike-api-introduction-for-developers'
        )
    ],
    crowdstrike_client_secret: Annotated[
        str, 
        Option(envvar='CROWDSTRIKE_CLIENT_SECRET', 
            prompt=True, 
            help='The API client secret to authenticate your API requests.\n'
                'https://falcon.crowdstrike.com/support/documentation/1/crowdstrike-api-introduction-for-developers'
        )
    ],
    crowdstrike_member_cid: Annotated[
        str, 
        Option(
            envvar='CROWDSTRIKE_MEMBER_CID', 
            help='For MSSP Master CIDs, optionally lock the token to act on behalf of this member CID'
    )] = None,
    tio_url: Annotated[
        str, Option(envvar='TIO_URL', help='TVM/TIO URL')
    ] = 'https://cloud.tenable.com',    
    log_level: Annotated[
        LogLevels, Option(envvar='LOG_LEVEL', help='Output logging level')
    ] = 'INFO',
    last_seen_days: Annotated[
        int, 
        Option(
            envvar='CROWDSTRIKE_LAST_SEEN_DAYS', 
            help='How many days back from today should we pull crowdstrike data for? '
    )] = 1,    
    download_vulns: Annotated[
        bool, Option(help='Import Falson Spotlight Vulndreability Findings?')
    ] = False,
) -> None:
    """
    Run the Crowdstrike connector
    """
    setup_logging(log_level)

    tvm = TenableIO(access_key=tio_access_key, secret_key=tio_secret_key, url=tio_url)
    crwd = CrowdStrikeAPI(
        url=crowdstrike_url,
        client_id=crowdstrike_client_id,
        client_secret=crowdstrike_client_secret,
        member_cid=crowdstrike_member_cid,
    )
    c2t1 = Transformer(tvm=tvm, crwd=crwd)
    c2t1.run(get_findings=download_vulns, last_seen_days=last_seen_days)


if __name__ == '__main__':
    app()