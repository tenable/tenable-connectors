"""
Asset XML to JSON Transform models for Qualys.

These models are based on a combination of the Qualys DTD documentation
and our own observations.

https://cdn2.qualys.com/docs/qualys-api-vmpc-xml-dtd-reference.pdf
"""

from datetime import datetime

from pydantic_xml import BaseXmlModel, RootXmlModel, attr, element

from .findings import DetectionList


class TruriskSeverityCount(BaseXmlModel, tag='VULN_COUNT'):
    severity: int = attr(name='qds_severity')
    count: int


class TruriskScoreFactors(BaseXmlModel, tag='TRURISK_SCORE_FACTORS'):
    formula: str | None = element(tag='TRURISK_SCORE_FORMULA', default=None)
    counts: list[TruriskSeverityCount]


class DnsData(BaseXmlModel, tag='DNS_DATA'):
    hostname: str | None = element(tag='HOSTNAME', default=None)
    domain: str | None = element(tag='DOMAIN', default=None)
    fqdn: str | None = element(tag='FQDN', default=None)


class Tag(BaseXmlModel, tag='TAG'):
    id: int = element(tag='TAG_ID')
    name: str = element(tag='NAME')


class TagList(RootXmlModel):
    root: list[Tag] | None = element(default=None)


class Host(BaseXmlModel, tag='HOST', search_mode='unordered'):
    id: int = element(tag='ID')
    asset_id: int = element(tag='ASSET_ID')
    ip: str | None = element(tag='IP', default=None)
    ipv6: str | None = element(tag='IPV6', default=None)
    asset_risk_score: int | None = element(tag='ASSET_RISK_SCORE', default=None)
    trurisk_score: int | None = element(tag='TRURISK_SCORE', default=None)
    trurisk: TruriskScoreFactors | None = element(default=None)
    tracking_method: str = element(tag='TRACKING_METHOD')
    dns: str | None = element(tag='DNS', default=None)
    dns_data: DnsData | None = element(default=None)
    ec2_instance_id: str | None = element(tag='EC2_INSTANCE_ID', default=None)
    cloud_provider: str | None = element(tag='CLOUD_PROVIDER', default=None)
    cloud_service: str | None = element(tag='CLOUD_SERVICE', default=None)
    cloud_resource_id: str | None = element(tag='CLOUD_RESOURCE_ID', default=None)
    netbios: str | None = element(tag='NETBIOS', default=None)
    os: str | None = element(tag='OS', default=None)
    os_cpe: str | None = element(tag='OS_CPE', default=None)
    qg_hostid: str | None = element(tag='QG_HOSTID', default=None)
    last_boot: datetime | None = element(tag='LAST_BOOT', default=None)
    serial_number: str | None = element(tag='SERIAL_NUMBER', default=None)
    hardware_uuid: str | None = element(tag='HARDWARE_UUID', default=None)
    first_found_date: datetime | None = element(tag='FIRST_FOUND_DATE', default=None)
    last_activity: datetime | None = element(tag='LAST_ACTIVITY', default=None)
    agent_status: str | None = element(tag='AGENT_STATUS', default=None)
    cloud_agent_running_on: str | None = element(
        tag='CLOUD_AGENT_RUNNING_ON', default=None
    )
    tags: TagList | None = element(tag='TAGS', default=None)
    last_vuln_scan_datetime: datetime | None = element(
        tag='LAST_VULN_SCAN_DATETIME', default=None
    )
    last_vm_scanned_date: datetime | None = element(
        tag='LAST_VM_SCANNED_DATE', default=None
    )
    last_vm_scanned_duration: int | None = element(
        tag='LAST_VM_SCANNED_DURATION', default=None
    )
    last_vm_auth_scanned_date: datetime | None = element(
        tag='LAST_VM_AUTH_SCANNED_DATE', default=None
    )
    last_vm_auth_scanned_duration: int | None = element(
        tag='LAST_VM_AUTH_SCANNED_DURATION', default=None
    )
    last_compliance_scan_datetime: datetime | None = element(
        tag='LAST_COMPLIANCE_SCAN_DATETIME', default=None
    )
    last_scap_scan_datetime: datetime | None = element(
        tag='LAST_SCAP_SCAN_DATETIME', default=None
    )
    last_pc_scanned_date: datetime | None = element(
        tag='LAST_PC_SCANNED_DATE', default=None
    )
    owner: str | None = element(tag='OWNER', default=None)
    comments: str | None = element(tag='COMMENTS', default=None)
    detections: DetectionList | None = element(default=None)

    # TODO: Need to see how the Metadata looks to map it.  See P336 of the Qualys DTD PDF
    #       https://cdn2.qualys.com/docs/qualys-api-vmpc-xml-dtd-reference.pdf
    # <!ELEMENT METADATA (EC2|GOOGLE|AZURE)+>
    # <!ELEMENT EC2 (ATTRIBUTE*)>
    # <!ELEMENT GOOGLE (ATTRIBUTE*)>
    # <!ELEMENT AZURE (ATTRIBUTE*)>
    # <!ELEMENT ATTRIBUTE
    # (NAME,LAST_STATUS,VALUE,LAST_SUCCESS_DATE?,LAST_ERROR_DATE?,LAST_ERROR?)>
    # <!ELEMENT LAST_STATUS (#PCDATA)>
    # <!ELEMENT LAST_SUCCESS_DATE (#PCDATA)>
    # <!ELEMENT LAST_ERROR_DATE (#PCDATA)>
    # <!ELEMENT LAST_ERROR (#PCDATA)>
    # <!ELEMENT CLOUD_PROVIDER_TAGS (CLOUD_TAG+)>
    # <!ELEMENT CLOUD_TAG (NAME, VALUE, LAST_SUCCESS_DATE)>
