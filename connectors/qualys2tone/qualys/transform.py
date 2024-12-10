"""
Data transform module.
"""

import logging
from typing import Any

from tenable.io import TenableIO

from .api import QualysAPI
from .database import Knowledgebase, init_db


class Transformer:
    """
    Main Qualys to TenableOne data transformer.
    """

    db: tuple

    def __init__(
        self,
        db_uri: str = 'sqlite:///cache.db',
        tvm: TenableIO | None = None,
        qualys: QualysAPI | None = None,
    ):
        """
        Initialze transformer

        Args:
            db_uri: The cache database location
            tvm: Optional TVM session to use
            qualys: Optional QualysVM session to use
        """
        self.db = init_db(db_uri)
        self.tvm = tvm if tvm else TenableIO()
        self.qualys = qualys if qualys else QualysAPI()
        self.log = logging.getLogger('Transformer')

    def run(self, get_kbs: bool = True, get_findings: bool = True):
        """
        Run the transformer

        Args:
            get_kbs:
                Should we retreive the KB arcles and cache them into
                a transitive database?
            get_findings:
                Should we get findings as well as asset metadata?
        """
        with self.tvm.sync.create(
            sync_id='tenable_qualys_vm',
            vendor='tenable',
            sensor='qualysguard',
        ) as job:
            self.log.info('Processing Qualys assets')
            self.log.debug(f'sync_id: {job.sync_id} uuid: {job.uuid}')
            for asset in self.qualys.assets.vuln():
                t1asset = self.transform_asset(asset)
                self.log.debug('Adding asset id=%s to the job' % t1asset['id'])
                job.add(t1asset, object_type='device-asset')

            if not get_findings:
                return
            elif get_findings and get_kbs:
                self.cache_knowledgebase()

            self.log.info('Processing Qualys vulnerabilities')
            for host in self.qualys.findings.vuln():
                for detection in host['detections']:
                    finding = self.transform_finding(detection, host['id'])
                    if finding:
                        self.log.debug(
                            'Adding finding id=%s to asset id=%s'
                            % (finding['id'], host['id'])
                        )
                        job.add(finding, object_type='cve-finding')

    def cache_knowledgebase(self) -> None:
        """
        Stores CVE metadata into the cache database

        Queries the Qualys Knowldegbase API and stores the CVE data into the cache for
        later use as the findings report does not contain the CVE data.
        """
        self.log.info('Collecting Qualys KB meta data')
        counter = 0
        with self.db.session() as session:
            for kb in self.qualys.knowledgebase.list():
                qid = kb['qid']
                cves = [i['id'] for i in kb.get('cves', [])]
                self.log.debug('Caching qid=%d cves=%s' % (qid, ','.join(cves)))
                session.add(Knowledgebase(id=qid, cves=cves))
                counter += 1
                if counter >= 1000:
                    session.commit()
            session.commit()

    def transform_finding(
        self,
        data: dict[str, Any],
        asset_id: int,
        max_cves: int = 128,
    ) -> dict[str, Any]:
        """
        Converts the raw Qualys finding into a T1-compatable cve-finding.
        """
        status_switch = {
            'New': 'ACTIVE',
            'Active': 'ACTIVE',
            'Fixed': 'INACTIVE',
            'Re-Opened': 'REOPENED',
        }
        sev_switch = {1: 'NONE', 2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL'}
        with self.db.session() as session:
            kb = (
                session.query(Knowledgebase)
                .filter(Knowledgebase.id == data['qid'])
                .one()
            )
            if len(kb.cves) == 0:
                self.log.info(
                    'Dropping asset=%s, finding=%s as there are no known cves.'
                    % (data['id'], asset_id)
                )
                return {}
            elif len(kb.cves) > max_cves:
                self.log.info(
                    'Truncating the first %s of %s cves for qid=%s due to T1 API restrictions.'
                    % (max_cves, len(kb.cves), data['qid'])
                )
            resp = {
                'object_type': 'cve-finding',
                'asset_id': str(asset_id),
                'id': str(data['id']),
                'definition_urn': f'qualys:{data["qid"]}',
                'state': status_switch.get(data.get('status'), 'ACTIVE'),
                'cve': {'cves': kb.cves[:max_cves]},
                'discovery': {
                    'first_observed_at': data.get('first_found'),
                    'last_observed_on': data.get('last_found'),
                },
                'exposure': {
                    'severity': {'level': sev_switch.get(data.get('severity'))}
                },
            }
        return resp

    def get_os_type(self, value: str | None) -> str | None:
        """
        leverages the OS value to determine the OS type.
        """
        if value and 'windows' in value.lower():
            return 'WINDOWS'
        elif value and 'linux' in value.lower():
            return 'LINUX'
        elif value and 'macos' in value.lower():
            return 'MAC_OS'

    def get_asset_criticality_level(self, value: int | None) -> str:
        """
        Determines the asset criticality based on the asset trurisk score.
        """
        if value and value >= 850:
            return 'CRITICAL'
        elif value and value >= 700:
            return 'HIGH'
        elif value and value >= 500:
            return 'MEDIUM'
        elif value and value < 500:
            return 'LOW'
        return 'NONE'

    def transform_asset(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Converts the raw Qualys asset into a T1-compatable device-asset
        """
        external_ids = []
        for key in ('asset_id', 'qg_hostid'):
            if data.get(key):
                external_ids.append({'qualifier': key, 'value': str(data.get(key))})
        return {
            'object_type': 'device-asset',
            'asset_class': 'DEVICE',
            'id': str(data['id']),
            'name': data.get('name'),
            'device': {
                'hardware': {
                    'bios': {'id': data.get('hardware_uuid')},
                    'serial_number': data.get('serial_number'),
                },
                'netbios_name': data.get('netbios'),
                'networking': {
                    'fqdns': [{'value': data['dns']}] if data.get('dns') else None,
                    'ip_addresses_v4': [{'address': data['ip']}]
                    if data.get('ip')
                    else None,
                    'ip_addresses_v6': [{'address': data['ipv6']}]
                    if data.get('ipv6')
                    else None,
                },
                'operating_system': {'type': self.get_os_type(data.get('os'))},
            },
            'external_ids': external_ids,
            'discovery': {
                'authentication': {
                    'attempted': data.get('last_vm_auth_scanned_date') is not None,
                    'successful': data.get('last_vm_auth_scanned_date') is not None,
                    'type': 'AGENT' if data.get('agent_status') else None,
                },
                'first_observed_at': data.get('first_found_date'),
                'last_observed_on': data.get('last_vm_scanned_date'),
            },
            'labels': [t['name'] for t in data.get('tags', [])],
            'exposure': {
                'criticality': {
                    'score': data.get('truerisk_score'),
                    'level': self.get_asset_criticality_level(
                        data.get('truerisk_score')
                    ),
                }
            },
        }
