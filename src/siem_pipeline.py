"""
SIEM Pipeline — Enterprise Security Information and Event Management

Orchestrates the full threat detection flow:
  ML Detection (Isolation Forest / DBSCAN)
       ↓
  Threat Intel APIs (VirusTotal, AbuseIPDB, OTX AlienVault,
                     CVE CIRCL, MalwareBazaar, IP-API)
       ↓
  Kafka Streaming Bus  (topics: anomaly-detections, threat-intel, security-alerts)
       ↓
  Elasticsearch Storage (indices: threat-detection-*)
       ↓
  Query / Dashboard layer
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import pandas as pd
from dotenv import load_dotenv

from src.elasticsearch_client import (
    INDEX_ALERTS,
    ThreatIntelElasticsearch,
)
from src.kafka_pipeline import (
    TOPIC_ANOMALY_DETECTIONS,
    TOPIC_SECURITY_ALERTS,
    TOPIC_THREAT_INTEL,
    ThreatEventConsumer,
    ThreatEventProducer,
)

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)


class SIEMPipeline:
    """
    Central orchestrator for the AI Threat Detection SIEM.

    Responsibilities:
      - Accept anomaly DataFrames from ML detection and publish to Kafka + Elasticsearch
      - Accept threat intel results (VirusTotal, IPs, CVEs) and index them
      - Run the Kafka consumer loop that routes events to Elasticsearch
      - Expose pipeline health / index-count status
    """

    def __init__(self):
        logger.info("Initializing SIEM Pipeline...")
        self.producer = ThreatEventProducer()
        self.es_client = ThreatIntelElasticsearch()
        self._log_status()

    def _log_status(self):
        kafka_state = "connected" if self.producer.connected else "offline (Kafka not running)"
        es_state = "connected" if self.es_client.connected else "offline (ES not running)"
        logger.info(f"  Kafka:         {kafka_state}")
        logger.info(f"  Elasticsearch: {es_state}")

    # ------------------------------------------------------------------
    # Anomaly Detection → SIEM
    # ------------------------------------------------------------------

    def process_anomalies(self, anomalies_df: pd.DataFrame) -> Dict:
        """
        Send ML-detected anomalies through the SIEM pipeline.

        Steps:
          1. Publish each record to the 'anomaly-detections' Kafka topic
          2. Bulk-index all records into Elasticsearch
          3. Fire a high-severity alert if any record is High/Critical

        Args:
            anomalies_df: DataFrame of anomaly records from detect_anomalies_isolation_forest()

        Returns:
            dict with 'kafka' and 'elasticsearch' result summaries
        """
        if anomalies_df.empty:
            logger.info("No anomalies to process")
            return {
                'kafka': {'success': 0, 'failed': 0, 'total': 0},
                'elasticsearch': {'success': 0, 'failed': 0, 'total': 0},
            }

        records = anomalies_df.to_dict(orient='records')
        logger.info(f"Processing {len(records)} anomalies through SIEM pipeline")

        # --- Kafka ---
        kafka_results = {'success': 0, 'failed': 0, 'total': len(records)}
        for record in records:
            if self.producer.publish_anomaly(record):
                kafka_results['success'] += 1
            else:
                kafka_results['failed'] += 1

        # --- Elasticsearch ---
        es_results = self.es_client.bulk_index_anomalies(records)

        # --- High-severity alert ---
        if 'Severity Level' in anomalies_df.columns:
            high_sev = anomalies_df[
                anomalies_df['Severity Level'].str.lower().isin(['high', 'critical'])
            ]
            if not high_sev.empty:
                attack_counts = (
                    high_sev['Attack Type'].value_counts().to_dict()
                    if 'Attack Type' in high_sev.columns
                    else {}
                )
                self.producer.publish_alert(
                    severity='high',
                    message=f"{len(high_sev)} high/critical severity anomalies detected",
                    context={
                        'count': len(high_sev),
                        'attack_types': attack_counts,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                    },
                )

        logger.info(f"Anomaly pipeline complete — Kafka: {kafka_results}, ES: {es_results}")
        return {'kafka': kafka_results, 'elasticsearch': es_results}

    # ------------------------------------------------------------------
    # Threat Intelligence → SIEM
    # ------------------------------------------------------------------

    def process_virustotal_results(self, results: List[Dict]) -> Dict:
        """
        Index VirusTotal scan results into Elasticsearch and stream to Kafka.
        Fires a high-severity alert for any malicious file detected.
        """
        es_count = 0
        for result in results:
            if self.es_client.index_virustotal_result(result):
                es_count += 1
            self.producer.publish_threat_intel('virustotal', result)

            if result.get('status') == 'malicious':
                self.producer.publish_alert(
                    severity='high',
                    message=f"Malicious file detected: {result.get('description', result.get('hash', 'unknown'))}",
                    context=result,
                )

        logger.info(f"VirusTotal: indexed {es_count}/{len(results)} results to Elasticsearch")
        return {'indexed': es_count, 'total': len(results)}

    def process_ip_geolocation(self, results: List[Dict]) -> Dict:
        """Index IP geolocation results (from IP-API) into Elasticsearch."""
        es_count = sum(1 for r in results if self.es_client.index_ip_geolocation(r))
        logger.info(f"IP Geolocation: indexed {es_count}/{len(results)} records")
        return {'indexed': es_count, 'total': len(results)}

    def process_cve_data(self, cve_list: List[Dict]) -> Dict:
        """Index CVE vulnerability records into Elasticsearch."""
        es_count = sum(1 for cve in cve_list if self.es_client.index_cve(cve))
        logger.info(f"CVEs: indexed {es_count}/{len(cve_list)} records")
        return {'indexed': es_count, 'total': len(cve_list)}

    def process_threat_analysis_results(self, results: Dict) -> Dict:
        """
        Process the full results dict from run_threat_analysis.run_analysis().
        Dispatches virustotal, ip_geolocation, and cve_data sections to their handlers.
        """
        summary = {}
        if results.get('virustotal'):
            summary['virustotal'] = self.process_virustotal_results(results['virustotal'])
        if results.get('ip_geolocation'):
            summary['ip_geolocation'] = self.process_ip_geolocation(results['ip_geolocation'])
        if results.get('cve_data'):
            summary['cve_data'] = self.process_cve_data(results['cve_data'])
        return summary

    # ------------------------------------------------------------------
    # Kafka Consumer → Elasticsearch routing
    # ------------------------------------------------------------------

    def start_consumer(self, max_messages: int = 500) -> int:
        """
        Start the Kafka consumer loop.

        Reads events from all three security topics and routes each event to
        the appropriate Elasticsearch index based on event_type:
          - 'anomaly_detected'  → INDEX_ANOMALIES
          - 'threat_intel'      → INDEX_THREAT_INTEL (dispatched by intel_type)
          - 'security_alert'    → INDEX_ALERTS

        Args:
            max_messages: Maximum number of messages to consume before stopping

        Returns:
            Number of messages processed
        """
        consumer = ThreatEventConsumer()
        consumer.connect()

        def handle_anomaly(event: Dict):
            self.es_client.index_anomaly(event)

        def handle_threat_intel(event: Dict):
            intel_type = event.get('intel_type', 'unknown')
            data = event.get('data', {})
            if intel_type == 'virustotal':
                self.es_client.index_virustotal_result(data)
            elif intel_type in ('ip_geolocation', 'ip-api'):
                self.es_client.index_ip_geolocation(data)
            elif intel_type == 'cve':
                self.es_client.index_cve(data)
            else:
                from src.elasticsearch_client import INDEX_THREAT_INTEL
                self.es_client.index_document(INDEX_THREAT_INTEL, {
                    'intel_type': intel_type,
                    'raw_data': data,
                })

        def handle_alert(event: Dict):
            self.es_client.index_document(INDEX_ALERTS, event)

        consumer.register_handler('anomaly_detected', handle_anomaly)
        consumer.register_handler('threat_intel', handle_threat_intel)
        consumer.register_handler('security_alert', handle_alert)

        logger.info(f"Starting SIEM consumer (max_messages={max_messages})...")
        processed = consumer.consume(max_messages=max_messages)
        consumer.close()

        return len(processed)

    # ------------------------------------------------------------------
    # Status & Reporting
    # ------------------------------------------------------------------

    def get_pipeline_status(self) -> Dict:
        """Return connection status and Elasticsearch index document counts."""
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'kafka': {
                'connected': self.producer.connected,
                'bootstrap_servers': self.producer.bootstrap_servers if self.producer.connected else [],
                'topics': [TOPIC_ANOMALY_DETECTIONS, TOPIC_THREAT_INTEL, TOPIC_SECURITY_ALERTS],
            },
            'elasticsearch': self.es_client.get_threat_summary(),
        }

    def print_status(self):
        """Print a human-readable pipeline status summary."""
        status = self.get_pipeline_status()
        print("\n" + "=" * 60)
        print("           SIEM PIPELINE STATUS")
        print("=" * 60)
        print(f"Timestamp : {status['timestamp']}")
        kafka_ok = status['kafka']['connected']
        es_data = status['elasticsearch']
        es_ok = es_data.get('status') == 'connected'
        print(f"\nKafka         : {'✅ Connected' if kafka_ok else '⚠️  Offline'}")
        if kafka_ok:
            print(f"  Bootstrap   : {status['kafka']['bootstrap_servers']}")
            print(f"  Topics      : {', '.join(status['kafka']['topics'])}")
        print(f"\nElasticsearch : {'✅ Connected' if es_ok else '⚠️  Offline'}")
        if es_ok and es_data.get('indices'):
            print("\n  Index Document Counts:")
            for idx, count in es_data['indices'].items():
                print(f"    {idx}: {count}")
        print("=" * 60)


# ---------------------------------------------------------------------------
# CLI entry-point — run standalone to check pipeline status
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    pipeline = SIEMPipeline()
    pipeline.print_status()
