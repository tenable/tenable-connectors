"""
XML Datastream handler.

The generator used from this module handles stream-parsing the
XML ducuments returned by Qualys and converte them one-at-a-time
into JSON through the Pydantic XML models stored within the
models sub-pkg.  This has provien to be a memory efficient way to
handle this kind of transform, even through it required modeling
as much of the report as we needed.
"""

from time import sleep
from typing import Any

from defusedxml.ElementTree import iterparse, tostring
from pydantic_xml import BaseXmlModel
from restfly.errors import APIError
from restfly.session import APISession

from .models.response import Warning


def handle_request(
    api: APISession,
    url: str,
    params: dict[str, Any] | None = None,
    retries: int = 5,
    delay: int = 30,
):
    """
    Simple retry handler for the XML handler function.

    Args:
        api: APISession to use to make the calls
        url: Url path to call for the page
        params: Query parameters to pass with the Url
        retries:
            Upon receiving a 400 response, how many times
            to retry the same call.
        delay:
            How long to wait between failed calls?
    """
    exc = None
    retry_counter = 0
    while True:
        try:
            resp = api.get(url, params=params, stream=True)
        except APIError as err:
            exc = err
            retry_counter += 1
            if retry_counter > retries:
                raise APIError(resp=exc.response) from exc
            sleep(delay)
        else:
            resp.raw.decode_content = True
            return resp


def xml_handler(
    api: APISession,
    path: str,
    params: dict[str, Any],
    model: BaseXmlModel,
    tag: str,
):
    """
    XML stream parser generator.

    Args:
        api: APISession to use to make the calls
        path: Url path to call for the pages
        params: Query parameters to pass to each call
        model: PydanticXML model to use for the transform
        tag:
            The XML tage to use as the root for the pydantic
            model that was passed.
    """
    next_url = None
    is_done = False

    resp = handle_request(api, path, params=params)
    while not is_done:
        events = iterparse(resp.raw, events=('end',))
        for _, elem in events:
            if elem.tag == 'WARNING':
                warning = Warning.from_xml(tostring(elem)).model_dump()
                next_url = warning['url']
            if elem.tag == tag:
                yield model.from_xml(tostring(elem)).model_dump(exclude_none=True)
                elem.clear()
        if next_url:
            resp = handle_request(api, next_url)
            next_url = None
        else:
            is_done = True
