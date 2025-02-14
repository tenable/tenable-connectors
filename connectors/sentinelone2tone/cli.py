#!/usr/bin/env python3
import logging
from enum import Enum

from rich.logging import RichHandler
from tenable.io import TenableIO
from typer import Option, Typer
from typing_extensions import Annotated

from sentinelone import __version__ as version
from sentinelone.api.session import SentinelOneAPI
from sentinelone.transform import Transformer

app = Typer()


class LogLevels(str, Enum):
    debug = 'DEBUG'
    info = 'INFO'
    warn = 'WARN'
    error = 'ERROR'


def setup_logging(log_level: LogLevels) -> None:
    """
    Setup logging for s1 integration
    """
    fileHandler = logging.FileHandler('sentinelone2tone.log')
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
    s1_api_token: Annotated[
        str, Option(envvar='S1_API_TOKEN', prompt=True, help='SentienlOne API Token')
    ],
    s1_url: Annotated[
        str, Option(envvar='S1_URL', prompt=True, help='SentinelOne URL')
    ],
    tio_url: Annotated[
        str, Option(envvar='TIO_URL', help='TVM/TIO URL')
    ] = 'https://cloud.tenable.com',
    log_level: Annotated[
        LogLevels, Option(envvar='LOG_LEVEL', help='Output logging level')
    ] = 'INFO',
    download_vulns: Annotated[
        bool, Option(help='Import the SentinelOne Vulndreability Findings')
    ] = True,
) -> None:
    """
    Run the Sentinel One connector
    """
    setup_logging(log_level)

    tvm = TenableIO(
        access_key=tio_access_key,
        secret_key=tio_secret_key,
        url=tio_url,
        vendor='Tenable',
        product='SentinelOne2ToneSyncConnector',
        build=version,
    )
    s1 = SentinelOneAPI(api_token=s1_api_token, url=s1_url)
    d2t1 = Transformer(tvm=tvm, s1=s1)
    d2t1.run(get_findings=download_vulns)


if __name__ == '__main__':
    app()
