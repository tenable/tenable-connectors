"""
Finding/Vuln XML to JSON Transform models for Qualys.

These models are based on a combination of the Qualys DTD documentation
and our own observations.

https://cdn2.qualys.com/docs/qualys-api-vmpc-xml-dtd-reference.pdf
"""

from datetime import datetime

from pydantic_xml import BaseXmlModel, RootXmlModel, attr, element


class QDS(BaseXmlModel, tag='QDS'):
    severity: str = attr()
    score: int


class QDSFactor(BaseXmlModel):
    name: str = attr()
    value: str


class QDSFactorList(RootXmlModel):
    root: list[QDSFactor] = element(tag='QDS_FACTOR', default=[])


class Detection(BaseXmlModel, tag='DETECTION', search_mode='unordered'):
    id: int = element(tag='UNIQUE_VULN_ID')
    qid: int = element(tag='QID')
    type: str = element(tag='TYPE')
    port: int | None = element(tag='PORT', default=None)
    protocol: str | None = element(tag='PROTOCOL', default=None)
    severity: int = element(tag='SEVERITY')
    fqdn: str | None = element(tag='FQDN', default=None)
    ssl: bool = element(tag='SSL')
    oracle_instance: str | None = element(tag='INSTANCE', default=None)
    result_instance: str | None = element(tag='RESULT_INSTANCE', default=None)
    results: str | None = element(tag='RESULTS', default=None)
    status: str | None = element(tag='STATUS', default=None)
    first_found: datetime | None = element(tag='FIRST_FOUND_DATTIME', default=None)
    last_found: datetime | None = element(tag='LAST_FOUND_DATETIME', default=None)
    qds: QDS | None = element(default=None)
    qds_factors: QDSFactorList | None = element(tag='QDS_FACTORS', default=None)
    times_found: int | None = element(tag='TIMES_FOUND', default=None)
    last_test: datetime | None = element(tag='LAST_TEST_DATETIME', default=None)
    last_update: datetime | None = element(tag='LAST_UPDATE_DATETIME', default=None)
    last_fixed: datetime | None = element(tag='LAST_FIXED_DATETIME', default=None)
    first_reopened: datetime | None = element(
        tag='FIRST_REOPENED_DATETIME', default=None
    )
    last_reopened: datetime | None = element(tag='LAST_REOPENED_DATETIME', default=None)
    times_reopened: int | None = element(tag='TIMES_REOPENED', default=None)
    service: str | None = element(tag='SERVICE', default=None)
    is_ignored: bool = element(tag='IS_IGNORED')
    is_disabled: bool = element(tag='IS_DISABLED')
    affect_running_kernel: int | None = element(
        tag='AFFECT_RUNNING_KERNEL', default=None
    )
    affect_running_service: int | None = element(
        tag='AFFECT_RUNNING_SERVICE', default=None
    )
    affect_exploitable_config: int | None = element(
        tag='AFFECT_EXPLOITABLE_CONFIG', default=None
    )
    last_processed: datetime | None = element(
        tag='LAST_PROCESSED_DATETIME', default=None
    )
    # <!ELEMENT ASSET_CVE (#PCDATA)> is not included in the output.


class DetectionList(RootXmlModel, tag='DETECTION_LIST'):
    root: list[Detection] | None = element(default=None)
