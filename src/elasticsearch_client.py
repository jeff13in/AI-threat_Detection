"""
Elasticsearch Client for AI Threat Detection SIEM
Manages index creation, mappings, document indexing, and querying
for all threat intelligence and anomaly data.
"""

import logging
import os
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Index name constants
# ---------------------------------------------------------------------------
INDEX_ANOMALIES    = 'threat-detection-anomalies'
INDEX_THREAT_INTEL = 'threat-detection-intel'
INDEX_ALERTS       = 'threat-detection-alerts'
INDEX_IP_REPUTATION = 'threat-detection-ip-reputation'
INDEX_CVES         = 'threat-detection-cves'

ALL_INDICES = [INDEX_ANOMALIES, INDEX_THREAT_INTEL, INDEX_ALERTS, INDEX_IP_REPUTATION, INDEX_CVES]

# ---------------------------------------------------------------------------
# Index mappings (enterprise SIEM schema)
# ---------------------------------------------------------------------------
INDEX_MAPPINGS: Dict[str, Dict] = {
    INDEX_ANOMALIES: {
        'mappings': {
            'properties': {
                '@timestamp':          {'type': 'date'},
                'event_type':          {'type': 'keyword'},
                'source_ip':           {'type': 'ip'},
                'destination_ip':      {'type': 'ip'},
                'attack_type':         {'type': 'keyword'},
                'severity':            {'type': 'keyword'},
                'anomaly_score':       {'type': 'float'},
                'protocol':            {'type': 'keyword'},
                'source_port':         {'type': 'integer'},
                'destination_port':    {'type': 'integer'},
                'packet_length':       {'type': 'integer'},
                'malware_indicators':  {'type': 'keyword'},
                'detection_method':    {'type': 'keyword'},
            }
        },
        'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
    },
    INDEX_THREAT_INTEL: {
        'mappings': {
            'properties': {
                '@timestamp':     {'type': 'date'},
                'intel_type':     {'type': 'keyword'},
                'source':         {'type': 'keyword'},
                'indicator':      {'type': 'keyword'},
                'threat_level':   {'type': 'keyword'},
                'detection_rate': {'type': 'keyword'},
                'status':         {'type': 'keyword'},
                'country':        {'type': 'keyword'},
                'isp':            {'type': 'text'},
                'raw_data':       {'type': 'object', 'enabled': False},
            }
        },
        'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
    },
    INDEX_ALERTS: {
        'mappings': {
            'properties': {
                '@timestamp': {'type': 'date'},
                'event_type': {'type': 'keyword'},
                'severity':   {'type': 'keyword'},
                'message':    {'type': 'text'},
                'context':    {'type': 'object', 'enabled': False},
            }
        },
        'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
    },
    INDEX_IP_REPUTATION: {
        'mappings': {
            'properties': {
                '@timestamp':       {'type': 'date'},
                'ip_address':       {'type': 'ip'},
                'country':          {'type': 'keyword'},
                'country_code':     {'type': 'keyword'},
                'city':             {'type': 'keyword'},
                'isp':              {'type': 'text'},
                'abuse_confidence': {'type': 'integer'},
                'is_malicious':     {'type': 'boolean'},
                'source':           {'type': 'keyword'},
            }
        },
        'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
    },
    INDEX_CVES: {
        'mappings': {
            'properties': {
                '@timestamp':     {'type': 'date'},
                'cve_id':         {'type': 'keyword'},
                'state':          {'type': 'keyword'},
                'date_published': {
                    'type': 'date',
                    'format': 'strict_date_optional_time||epoch_millis||yyyy-MM-dd',
                },
                'title':          {'type': 'text'},
                'description':    {'type': 'text'},
            }
        },
        'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
    },
}


class ThreatIntelElasticsearch:
    """
    Elasticsearch client for the SIEM threat detection pipeline.

    Provides:
      - Auto-creation of indices with typed mappings on first connect
      - Single-document and bulk indexing helpers
      - Typed indexing methods for anomalies, VirusTotal, IP reputation, CVEs
      - Query helpers for dashboards and reporting
      - Graceful offline-mode fallback when Elasticsearch is unavailable
    """

    def __init__(self, hosts: Optional[List[str]] = None):
        es_url = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
        self.hosts = hosts or [es_url]
        self._es_user = os.getenv('ELASTICSEARCH_USER')
        self._es_password = os.getenv('ELASTICSEARCH_PASSWORD')
        self._es_api_key = os.getenv('ELASTICSEARCH_API_KEY')
        self.es = None
        self.connected = False
        self._connect()

    def _connect(self):
        try:
            from elasticsearch import Elasticsearch
            # Warn if connecting over plain HTTP to a non-localhost host
            for host in self.hosts:
                if host.startswith('http://') and 'localhost' not in host and '127.0.0.1' not in host:
                    warnings.warn(
                        f"Elasticsearch host '{host}' uses HTTP without TLS. "
                        "Use HTTPS in non-local deployments.",
                        stacklevel=2,
                    )

            kwargs: Dict[str, Any] = {
                'request_timeout': 10,
                'retry_on_timeout': True,
                'max_retries': 2,
            }
            if self._es_api_key:
                kwargs['api_key'] = self._es_api_key
            elif self._es_user and self._es_password:
                kwargs['http_auth'] = (self._es_user, self._es_password)

            self.es = Elasticsearch(self.hosts, **kwargs)
            if self.es.ping():
                self.connected = True
                logger.info(f"Elasticsearch connected at {self.hosts}")
                self._ensure_indices()
            else:
                logger.warning("Elasticsearch ping failed — running in offline mode")
        except Exception as e:
            logger.warning(f"Elasticsearch unavailable, running in offline mode: {e}")

    def _ensure_indices(self):
        """Create all SIEM indices with their mappings if they do not exist yet."""
        for index_name, body in INDEX_MAPPINGS.items():
            try:
                if not self.es.indices.exists(index=index_name):
                    self.es.indices.create(index=index_name, body=body)
                    logger.info(f"Created index: {index_name}")
            except Exception as e:
                logger.error(f"Failed to create index '{index_name}': {e}")

    # ------------------------------------------------------------------
    # Core indexing primitives
    # ------------------------------------------------------------------

    def index_document(self, index: str, doc: Dict, doc_id: Optional[str] = None) -> bool:
        """Index a single document. Adds @timestamp if missing. Returns True on success."""
        if not self.connected:
            logger.debug(f"[OFFLINE] Would index to '{index}': {list(doc.keys())}")
            return False
        try:
            doc.setdefault('@timestamp', datetime.now(timezone.utc).isoformat())
            self.es.index(index=index, body=doc, id=doc_id)
            return True
        except Exception as e:
            logger.error(f"Failed to index document to '{index}': {e}")
            return False

    def bulk_index(self, index: str, documents: List[Dict]) -> Dict:
        """
        Bulk-index a list of documents into the given index.
        Returns {'success': int, 'failed': int, 'total': int}.
        """
        if not self.connected:
            logger.debug(f"[OFFLINE] Would bulk-index {len(documents)} docs to '{index}'")
            return {'success': 0, 'failed': len(documents), 'total': len(documents)}

        from elasticsearch.helpers import bulk

        actions = []
        for doc in documents:
            doc.setdefault('@timestamp', datetime.now(timezone.utc).isoformat())
            actions.append({'_index': index, '_source': doc})

        try:
            success, errors = bulk(self.es, actions, raise_on_error=False)
            failed = len(errors) if isinstance(errors, list) else 0
            logger.info(f"Bulk indexed {success}/{len(documents)} docs to '{index}'")
            return {'success': success, 'failed': failed, 'total': len(documents)}
        except Exception as e:
            logger.error(f"Bulk index error on '{index}': {e}")
            return {'success': 0, 'failed': len(documents), 'total': len(documents)}

    # ------------------------------------------------------------------
    # Typed indexing helpers
    # ------------------------------------------------------------------

    def bulk_index_anomalies(self, anomalies: List[Dict]) -> Dict:
        """
        Bulk-index anomaly detection records from the Isolation Forest output.
        Accepts raw DataFrame rows (dict) with dataset column names.
        """
        docs = []
        for a in anomalies:
            try:
                source_port = a.get('Source Port', 0)
                dest_port = a.get('Destination Port', 0)
                packet_len = a.get('Packet Length', 0)
                docs.append({
                    '@timestamp':         datetime.now(timezone.utc).isoformat(),
                    'event_type':         'anomaly_detected',
                    'source_ip':          str(a.get('Source IP Address', '')),
                    'destination_ip':     str(a.get('Destination IP Address', '')),
                    'attack_type':        str(a.get('Attack Type', 'Unknown')),
                    'severity':           str(a.get('Severity Level', 'Unknown')),
                    'anomaly_score':      float(a.get('IF_Anomaly_Score', 0) or 0),
                    'protocol':           str(a.get('Protocol', '')),
                    'source_port':        int(source_port) if source_port and str(source_port).isdigit() else 0,
                    'destination_port':   int(dest_port) if dest_port and str(dest_port).isdigit() else 0,
                    'packet_length':      int(packet_len) if packet_len and str(packet_len).isdigit() else 0,
                    'malware_indicators': str(a.get('Malware Indicators', '')),
                    'detection_method':   'isolation_forest',
                })
            except Exception as e:
                logger.warning(f"Skipping anomaly record due to conversion error: {e}")

        return self.bulk_index(INDEX_ANOMALIES, docs)

    def index_anomaly(self, anomaly: Dict) -> bool:
        """Index a single anomaly event (Kafka consumer format or raw dataset row)."""
        doc = {
            '@timestamp':         anomaly.get('timestamp', datetime.now(timezone.utc).isoformat()),
            'event_type':         'anomaly_detected',
            'source_ip':          str(anomaly.get('source_ip', anomaly.get('Source IP Address', ''))),
            'destination_ip':     str(anomaly.get('destination_ip', anomaly.get('Destination IP Address', ''))),
            'attack_type':        str(anomaly.get('attack_type', anomaly.get('Attack Type', 'Unknown'))),
            'severity':           str(anomaly.get('severity', anomaly.get('Severity Level', 'Unknown'))),
            'anomaly_score':      float(anomaly.get('anomaly_score', anomaly.get('IF_Anomaly_Score', 0)) or 0),
            'protocol':           str(anomaly.get('protocol', anomaly.get('Protocol', ''))),
            'malware_indicators': str(anomaly.get('malware_indicators', anomaly.get('Malware Indicators', ''))),
            'detection_method':   anomaly.get('detection_method', 'isolation_forest'),
        }
        return self.index_document(INDEX_ANOMALIES, doc)

    def index_virustotal_result(self, result: Dict) -> bool:
        """Index a VirusTotal scan result into the threat-intel index."""
        doc = {
            '@timestamp':     datetime.now(timezone.utc).isoformat(),
            'intel_type':     'virustotal',
            'source':         'virustotal',
            'indicator':      result.get('hash', ''),
            'status':         result.get('status', 'unknown'),
            'detection_rate': result.get('detection_rate', ''),
            'threat_level':   'high' if result.get('status') == 'malicious' else 'low',
            'raw_data':       result,
        }
        return self.index_document(INDEX_THREAT_INTEL, doc)

    def index_ip_geolocation(self, result: Dict) -> bool:
        """Index an IP geolocation record into the ip-reputation index."""
        doc = {
            '@timestamp':   datetime.now(timezone.utc).isoformat(),
            'ip_address':   result.get('ip_address', ''),
            'country':      result.get('country', 'Unknown'),
            'country_code': result.get('country_code', ''),
            'city':         result.get('city', 'Unknown'),
            'isp':          result.get('isp', 'Unknown'),
            'is_malicious': False,
            'source':       'ip-api',
        }
        return self.index_document(INDEX_IP_REPUTATION, doc)

    def index_ip_abuseipdb(self, ip_address: str, data: Dict) -> bool:
        """Index an AbuseIPDB reputation result."""
        abuse_data = data.get('data', data)
        doc = {
            '@timestamp':       datetime.now(timezone.utc).isoformat(),
            'ip_address':       ip_address,
            'country_code':     abuse_data.get('countryCode', ''),
            'abuse_confidence': int(abuse_data.get('abuseConfidencePercentage', 0) or 0),
            'is_malicious':     int(abuse_data.get('abuseConfidencePercentage', 0) or 0) > 50,
            'source':           'abuseipdb',
        }
        return self.index_document(INDEX_IP_REPUTATION, doc)

    def index_cve(self, cve: Dict) -> bool:
        """Index a CVE record — handles both raw CIRCL API format and simplified dicts."""
        cve_meta = cve.get('cveMetadata', {})
        containers = cve.get('containers', {}).get('cna', {})
        descriptions = containers.get('descriptions', [{}])
        desc_text = descriptions[0].get('value', '') if descriptions else ''

        doc = {
            '@timestamp':     datetime.now(timezone.utc).isoformat(),
            'cve_id':         cve_meta.get('cveId', cve.get('cve_id', 'Unknown')),
            'state':          cve_meta.get('state', cve.get('state', 'Unknown')),
            'date_published': cve_meta.get('datePublished', cve.get('date_published', '')) or '',
            'title':          containers.get('title', cve.get('title', '')),
            'description':    (desc_text or cve.get('description', ''))[:2000],
        }
        return self.index_document(INDEX_CVES, doc, doc_id=doc['cve_id'])

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def search(self, index: str, query: Dict, size: int = 100) -> List[Dict]:
        """Execute an Elasticsearch query DSL search and return source documents."""
        if not self.connected:
            logger.warning("Elasticsearch not connected — search unavailable")
            return []
        try:
            resp = self.es.search(index=index, body=query, size=size)
            return [hit['_source'] for hit in resp['hits']['hits']]
        except Exception as e:
            logger.error(f"Search error on '{index}': {e}")
            return []

    def get_recent_anomalies(self, hours: int = 24, size: int = 100) -> List[Dict]:
        """Return the most anomalous records from the last N hours, sorted by score."""
        query = {
            'query': {'range': {'@timestamp': {'gte': f'now-{hours}h', 'lte': 'now'}}},
            'sort': [{'anomaly_score': {'order': 'desc'}}],
        }
        return self.search(INDEX_ANOMALIES, query, size=size)

    def get_malicious_files(self) -> List[Dict]:
        """Return all VirusTotal entries flagged as malicious."""
        query = {'query': {'term': {'status': 'malicious'}}}
        return self.search(INDEX_THREAT_INTEL, query)

    def get_threat_summary(self) -> Dict:
        """Return document counts per index, plus connection status."""
        if not self.connected:
            return {'status': 'offline', 'indices': {}}
        summary: Dict[str, Any] = {'status': 'connected', 'indices': {}}
        for index in ALL_INDICES:
            try:
                summary['indices'][index] = self.es.count(index=index)['count']
            except Exception:
                summary['indices'][index] = 'unavailable'
        return summary
