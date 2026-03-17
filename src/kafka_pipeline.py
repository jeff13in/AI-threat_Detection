"""
Kafka Pipeline for AI Threat Detection System
Handles streaming of threat events and anomaly detections via Apache Kafka
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Kafka topic constants
TOPIC_ANOMALY_DETECTIONS = 'anomaly-detections'
TOPIC_THREAT_INTEL = 'threat-intel'
TOPIC_SECURITY_ALERTS = 'security-alerts'


def _get_bootstrap_servers() -> List[str]:
    kafka_url = os.getenv('KAFKA_URL', 'localhost:9092')
    return [s.strip() for s in kafka_url.split(',')]


class ThreatEventProducer:
    """
    Kafka producer for publishing threat events to security topics.
    Falls back to offline mode gracefully if Kafka is not running.
    """

    def __init__(self, bootstrap_servers: Optional[List[str]] = None):
        self.bootstrap_servers = bootstrap_servers or _get_bootstrap_servers()
        self.producer = None
        self.connected = False
        self._connect()

    def _connect(self):
        try:
            from kafka import KafkaProducer
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                acks='all',
                retries=3,
                max_block_ms=5000,
            )
            self.connected = True
            logger.info(f"Kafka producer connected to {self.bootstrap_servers}")
        except Exception as e:
            logger.warning(f"Kafka unavailable — running in offline mode: {e}")

    def publish(self, topic: str, event: Dict, key: Optional[str] = None) -> bool:
        """Publish a single event to a Kafka topic. Returns True on success."""
        if not self.connected:
            logger.debug(f"[OFFLINE] Skipping publish to '{topic}': {event.get('event_type', '?')}")
            return False
        try:
            future = self.producer.send(topic, value=event, key=key)
            future.get(timeout=5)
            return True
        except Exception as e:
            logger.error(f"Failed to publish to '{topic}': {e}")
            return False

    def publish_anomaly(self, record: Dict) -> bool:
        """
        Publish a single anomaly detection record to the anomaly-detections topic.
        Expects a dict with keys from the cybersecurity_attacks dataset.
        """
        event = {
            'event_type': 'anomaly_detected',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source_ip': str(record.get('Source IP Address', '')),
            'destination_ip': str(record.get('Destination IP Address', '')),
            'attack_type': str(record.get('Attack Type', 'Unknown')),
            'severity': str(record.get('Severity Level', 'Unknown')),
            'anomaly_score': float(record.get('IF_Anomaly_Score', 0)),
            'protocol': str(record.get('Protocol', '')),
            'source_port': record.get('Source Port', ''),
            'destination_port': record.get('Destination Port', ''),
            'packet_length': record.get('Packet Length', 0),
            'malware_indicators': str(record.get('Malware Indicators', '')),
            'detection_method': 'isolation_forest',
        }
        key = str(record.get('Source IP Address', 'unknown'))
        return self.publish(TOPIC_ANOMALY_DETECTIONS, event, key=key)

    def publish_threat_intel(self, intel_type: str, data: Dict) -> bool:
        """Publish a threat intelligence event (VirusTotal, OTX, etc.) to the threat-intel topic."""
        event = {
            'event_type': 'threat_intel',
            'intel_type': intel_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': data,
        }
        return self.publish(TOPIC_THREAT_INTEL, event, key=intel_type)

    def publish_alert(self, severity: str, message: str, context: Dict) -> bool:
        """Publish a high-level security alert to the security-alerts topic."""
        event = {
            'event_type': 'security_alert',
            'severity': severity,
            'message': message,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'context': context,
        }
        return self.publish(TOPIC_SECURITY_ALERTS, event, key=severity)

    def publish_batch(self, topic: str, events: List[Dict]) -> Dict:
        """Publish a batch of events; returns a summary dict with success/failed counts."""
        success, failed = 0, 0
        for event in events:
            if self.publish(topic, event):
                success += 1
            else:
                failed += 1
        if self.connected and self.producer:
            self.producer.flush()
        return {'success': success, 'failed': failed, 'total': len(events)}

    def close(self):
        if self.producer:
            self.producer.flush()
            self.producer.close()
            logger.info("Kafka producer closed")


class ThreatEventConsumer:
    """
    Kafka consumer that reads events from threat detection topics and
    dispatches them to registered handler functions (e.g. Elasticsearch indexer).
    """

    def __init__(
        self,
        topics: Optional[List[str]] = None,
        bootstrap_servers: Optional[List[str]] = None,
        group_id: str = 'threat-detection-siem',
    ):
        self.topics = topics or [TOPIC_ANOMALY_DETECTIONS, TOPIC_THREAT_INTEL, TOPIC_SECURITY_ALERTS]
        self.bootstrap_servers = bootstrap_servers or _get_bootstrap_servers()
        self.group_id = group_id
        self.consumer = None
        self.connected = False
        self._handlers: Dict[str, Callable] = {}

    def connect(self):
        try:
            from kafka import KafkaConsumer
            self.consumer = KafkaConsumer(
                *self.topics,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                value_deserializer=lambda v: json.loads(v.decode('utf-8')),
                auto_offset_reset='earliest',
                enable_auto_commit=False,
                consumer_timeout_ms=5000,
            )
            self.connected = True
            logger.info(f"Kafka consumer connected, subscribed to: {self.topics}")
        except Exception as e:
            logger.warning(f"Kafka consumer unavailable: {e}")

    def register_handler(self, event_type: str, handler: Callable):
        """
        Register a callable to handle a specific event_type.
        Use '*' as the event_type to catch all unhandled events.
        """
        self._handlers[event_type] = handler

    def consume(self, max_messages: int = 100) -> List[Dict]:
        """
        Consume up to max_messages from subscribed topics.
        Dispatches each message to its registered handler and returns processed events.
        """
        if not self.connected:
            logger.warning("Consumer not connected — cannot consume messages")
            return []

        processed = []
        count = 0
        try:
            for message in self.consumer:
                event = message.value
                event_type = event.get('event_type', 'unknown')
                handler = self._handlers.get(event_type) or self._handlers.get('*')
                handler_ok = True
                if handler:
                    try:
                        handler(event)
                    except Exception as e:
                        handler_ok = False
                        logger.error(f"Handler error for event_type='{event_type}': {e}")
                if handler_ok:
                    self.consumer.commit()
                    processed.append(event)
                count += 1
                if count >= max_messages:
                    break
        except Exception as e:
            logger.error(f"Error during message consumption: {e}")

        logger.info(f"Consumer processed {len(processed)} messages")
        return processed

    def close(self):
        if self.consumer:
            self.consumer.close()
            logger.info("Kafka consumer closed")
