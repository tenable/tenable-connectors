#!/usr/bin/env python3
import logging
from enum import Enum
from pathlib import Path

from rich.logging import RichHandler
from tenable.io import TenableIO
from typer import Option, Typer
from typing_extensions import Annotated

from qualys import __version__ as version
from qualys.api import QualysAPI
from qualys.transform import Transformer

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
    fileHandler = logging.FileHandler('qualys2tone.log')
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
    qualys_url: Annotated[
        str, Option(envvar='QUALYS_URL', prompt=True, help='Qualys API URL')
    ],
    qualys_username: Annotated[
        str, Option(envvar='QUALYS_USERNAME', prompt=True, help='Qualys API Username')
    ],
    qualys_password: Annotated[
        str,
        Option(
            envvar='QUALYS_PASSWORD',
            prompt=True,
            hide_input=True,
            help='Qualys API Password',
        ),
    ],
    log_level: Annotated[
        LogLevels, Option(envvar='LOG_LEVEL', help='Output logging level')
    ] = 'INFO',
    cache_file: Annotated[Path, Option(help='Local cache file')] = Path('cache.db'),
    flush_cache: Annotated[bool, Option(help='Flush any cache that exists?')] = True,
    download_kbs: Annotated[
        bool, Option(help='Download the Qualys knowledgebase?')
    ] = True,
    download_vulns: Annotated[
        bool, Option(help='Download the Qualys Findings?')
    ] = True,
) -> None:
    """
    Run the Qualys integration
    """
    setup_logging(log_level)

    if flush_cache:
        if cache_file.exists():
            logging.info('Removing old cache file.')
            cache_file.unlink()

    tvm = TenableIO(
        access_key=tio_access_key,
        secret_key=tio_secret_key,
        vendor='Tenable',
        product='QualysVM2ToneSyncConnector',
        build=version,
    )
    qualys = QualysAPI(
        url=qualys_url, username=qualys_username, password=qualys_password
    )
    q2t1 = Transformer(tvm=tvm, qualys=qualys, db_uri=f'sqlite:///{cache_file}')
    q2t1.run(get_kbs=download_kbs, get_findings=download_vulns)


if __name__ == '__main__':
    app()
