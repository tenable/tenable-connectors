"""
Base Report response models based on the Qualys DTD document
and from practical observations.
"""

from datetime import datetime

from pydantic_xml import BaseXmlModel, RootXmlModel, element

from .asset import Host


class HostList(RootXmlModel):
    root: list[Host]


class Warning(BaseXmlModel, tag='WARNING'):
    code: int | None = element(tag='CODE', default=None)
    text: str | None = element(tag='TEXT', default=None)
    url: str | None = element(tag='URL', default=None)


class Response(BaseXmlModel, tag='RESPONSE', search_mode='ordered'):
    timestamp: datetime = element(tag='DATETIME')
    hosts: HostList = element(tag='HOST_LIST')
    warning: Warning | None = element(tag='WARNING', default=None)


class APIResponse(BaseXmlModel):
    response: Response
