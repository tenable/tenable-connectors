from typing import Annotated

from pydantic import AnyHttpUrl, Field, SecretStr
from tenint import Connector, Credential, Settings, TenableCloudCredential

from trendmicro.transform import Transformer


class TrendMicroCredential(Credential):
    description: str = 'Trend Micro Credential'

    url: Annotated[
        AnyHttpUrl,
        Field(
            title='Trend Micro Region Domain URL',
            description='A valid Trend micro region domain URL',
        ),
    ]
    token: Annotated[
        SecretStr,
        Field(
            title='Trend Micro Authentication Token',
            description='The API authentication token to authenticate API requests.',
        ),
    ]


connector = Connector(
    settings=Settings, credentials=[TrendMicroCredential, TenableCloudCredential]
)


@connector.job
def main(config: Settings, since: int | None = None):
    """
    Trend Micro to Tenable One Connector.
    """

    transformer = Transformer()
    counts = transformer.run()
    return {'counts': counts}


if __name__ == '__main__':
    connector.app()
