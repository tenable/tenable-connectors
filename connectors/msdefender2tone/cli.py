#!/usr/bin/env python3
import logging
from enum import Enum

from msdefender.api.session import MSDefenderAPI
from msdefender.transform import Transformer
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
    fileHandler = logging.FileHandler('msdefender2tone.log')
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
    defender_tenant_id: Annotated[
        str, Option(envvar='MS_DEFENDER_TENANT_ID', prompt=True, help='MS Defender Tenant ID')
    ],
    defender_app_id: Annotated[ 
        str, Option(envvar='MS_DEFENDER_APP_ID', prompt=True, help='MS Defender App ID')
    ],
    defender_app_secret: Annotated[
        str, Option(
            envvar='MS_DEFENDER_APP_SECRET', 
            prompt=True, 
            hide_input=True,
            help='MS Defender App Secret Value')
    ],
    tio_url: Annotated[
        str, Option(envvar='TIO_URL', help='TVM/TIO URL')
    ] = 'https://cloud.tenable.com',    
    log_level: Annotated[
        LogLevels, Option(envvar='LOG_LEVEL', help='Output logging level')
    ] = 'INFO',
    download_vulns: Annotated[
        bool, Option(help='Import the MS Defender Vulndreability Findings?')
    ] = True,
) -> None:
    """
    Run the MS Defender connector
    """
    setup_logging(log_level)

    tvm = TenableIO(access_key=tio_access_key, secret_key=tio_secret_key, url=tio_url)
    defender = MSDefenderAPI(
        tenant_id=defender_tenant_id,
        app_id=defender_app_id,
        app_secret=defender_app_secret,
    )
    d2t1 = Transformer(tvm=tvm, defender=defender)
    d2t1.run(get_findings=download_vulns)


if __name__ == '__main__':
    app()
