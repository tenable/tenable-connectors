"""
Knowledgebase/Plugin XML to JSON Transform models for Qualys.

These models are based on a combination of the Qualys DTD documentation
and our own observations.

https://cdn2.qualys.com/docs/qualys-api-vmpc-xml-dtd-reference.pdf
"""

from datetime import datetime

from pydantic_xml import BaseXmlModel, RootXmlModel, element


class Software(BaseXmlModel):
    product: str | None = element(tag='PRODUCT')
    vendor: str | None = element(tag='VENDOR')


class Reference(BaseXmlModel):
    id: str = element(tag='ID')
    url: str = element(tag='URL')


class VendorReferenceList(RootXmlModel, tag='VENDOR_REFERENCE_LIST'):
    root: list[Reference] = element(tag='VENDOR_REFERENCE', default=[])


class SoftwareList(RootXmlModel, tag='SOFTWARE_LIST'):
    root: list[Software] = element(tag='SOFTWARE', default=[])


class CVEList(RootXmlModel, tag='CVE_LIST'):
    root: list[Reference] = element(tag='CVE', default=[])


class BugTraqList(RootXmlModel, tag='BUGTRAQ_LIST'):
    root: list[Reference] = element(tag='BUGTRAQ', default=[])


class CvssInfo(BaseXmlModel):
    base: float | None = element(tag='BASE', default=None)
    temporal: float | None = element(tag='TEMPORAL', default=None)
    vector: str | None = element(tag='VECTOR_STRING', default=None)


class KnowledgebaseVuln(BaseXmlModel, tag='VULN', search_mode='unordered'):
    qid: int = element(tag='QID')
    vuln_type: str = element(tag='VULN_TYPE')
    severity_level: int = element(tag='SEVERITY_LEVEL')
    title: str = element(tag='TITLE')
    last_modified: datetime = element(tag='LAST_SERVICE_MODIFICATION_DATETIME')
    published: datetime = element(tag='PUBLISHED_DATETIME')
    patchable: bool = element(tag='PATCHABLE')
    software: SoftwareList | None = element(default=None)
    vendor_references: VendorReferenceList | None = element(default=None)
    cves: CVEList | None = element(default=None)
    cvss_v2: CvssInfo = element(tag='CVSS', default=None)
    cvss_v3: CvssInfo = element(tag='CVSS_V3', default=None)
    diagnosis: str | None = element(tag='DIAGNOSIS', default=None)
    consequence: str | None = element(tag='CONSEQUENCE', default=None)
    solution: str | None = element(tag='SOLUTION', default=None)
