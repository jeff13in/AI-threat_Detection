# `src/` — Architecture & Data Flow

## Overview

The `src/` folder is the **core engine** of the AI Threat Detection system. It contains 5 modules that together form a complete enterprise SIEM pipeline. Each module has a single, clear responsibility, and they are layered so that data flows from collection → streaming → storage in a clean pipeline pattern.

---

## Module Breakdown

### 1. `src/setup.py` — Environment Bootstrap

The simplest module. It runs at startup and:
- Loads all environment variables from `.env` (API keys, service URLs)
- Exposes three constants: `ELASTICSEARCH_URL`, `KAFKA_URL`, `REDIS_URL`
- Provides `log_setup()` to print the current configuration

**Role in architecture:** Foundation layer — every other module depends on the `.env` values this loads.

---

### 2. `src/data_collector.py` — Threat Intelligence Collection

The **data ingestion layer**. Communicates with 6 external threat intelligence APIs and persists results to a local SQLite database.

#### Key class: `ThreatDataCollector`

**Initialization:**
- Creates a `requests.Session` with a custom `User-Agent`
- Initializes SQLite at `data/threat_intel.db` with 3 tables
- Loads all API keys from environment variables
- Optionally creates a `ThreatEventProducer` (Kafka) for real-time streaming

**SQLite Tables:**

| Table | Purpose |
|-------|---------|
| `api_responses` | Raw response cache with MD5 deduplication key |
| `threat_indicators` | Normalized indicators (IPs, hashes, domains) with threat level |
| `ip_reputation` | IP-specific reputation scores and country data |

**API Methods:**

| Method | API | Auth | What it fetches |
|--------|-----|------|-----------------|
| `check_ip_reputation_abuseipdb(ip)` | AbuseIPDB | Key required | Abuse confidence score (0–100%), country, reports |
| `get_ip_geolocation(ip)` | IP-API | Free | Country, city, ISP, lat/lon |
| `check_file_virustotal(hash)` | VirusTotal v3 | Key required | Malicious/suspicious engine count for a file hash |
| `get_otx_indicators(type, value)` | OTX AlienVault | Key required | Threat pulse details for IP/domain/hash |
| `get_latest_cves()` | CVE CIRCL | Free | Latest published CVE vulnerability records |
| `get_malware_samples(limit)` | MalwareBazaar | Key required | Recent malware sample metadata |

**`collect_daily_threat_intel()`** — the main orchestration method:
1. Checks 4 sample IPs against AbuseIPDB + IP-API
2. Fetches latest CVEs
3. Fetches recent malware samples from MalwareBazaar
4. Fetches OTX threat pulses
5. Stores every response in SQLite via `store_api_response()`
6. **If Kafka is running:** streams all successful responses to the `threat-intel` topic

---

### 3. `src/kafka_pipeline.py` — Real-Time Streaming Bus

The **event streaming layer**. Acts as the message bus between detection/collection and storage. Modeled on how enterprise SIEMs (Splunk, IBM QRadar) use message queues to decouple producers from consumers.

#### Topics

| Topic | Purpose |
|-------|---------|
| `anomaly-detections` | ML-detected anomaly events from Isolation Forest |
| `threat-intel` | Enrichment data from the 6 threat intelligence APIs |
| `security-alerts` | High-severity synthesized alerts requiring action |

#### Class: `ThreatEventProducer`

Wraps `kafka-python`'s `KafkaProducer`. Key behaviors:
- Serializes all events to JSON with `default=str` (handles datetimes safely)
- Uses `acks='all'` — waits for all replicas to confirm before returning
- `max_block_ms=5000` — times out after 5 seconds if broker is unreachable
- Falls back to **offline mode silently** if Kafka is not running — no crash

**Publish methods:**

| Method | Topic | Event shape |
|--------|-------|-------------|
| `publish_anomaly(record)` | `anomaly-detections` | Source/dest IP, attack type, severity, anomaly score, protocol, ports |
| `publish_threat_intel(intel_type, data)` | `threat-intel` | intel_type tag + raw API data |
| `publish_alert(severity, message, context)` | `security-alerts` | Severity level + human message + context dict |
| `publish_batch(topic, events)` | any | Loops publish + flushes; returns success/failed counts |

#### Class: `ThreatEventConsumer`

Wraps `KafkaConsumer`. Key behaviors:
- Subscribes to all 3 topics by default
- Uses consumer group `threat-detection-siem` — enables horizontal scaling
- `auto_offset_reset='earliest'` — processes all past events on first run
- `consumer_timeout_ms=5000` — stops iteration after 5s of silence

**Handler registration pattern:**
```python
consumer.register_handler('anomaly_detected', fn)
consumer.register_handler('threat_intel', fn)
consumer.register_handler('*', fallback_fn)   # catch-all
```

---

### 4. `src/elasticsearch_client.py` — SIEM Storage & Search

The **persistent storage and query layer**. Elasticsearch is the industry standard for SIEM log storage (used in the ELK stack). This module manages schema, indexing, and queries.

#### Indices (5 total, all prefixed `threat-detection-`)

**`threat-detection-anomalies`**
Stores ML-detected anomalies. Typed fields:
- `source_ip` / `destination_ip` → `ip` type (enables IP range queries and CIDR filtering)
- `anomaly_score` → `float` (sortable, aggregatable)
- `attack_type`, `severity`, `protocol` → `keyword` (exact match, aggregations)
- `@timestamp` → `date` (required for Kibana time-series dashboards)

**`threat-detection-intel`**
Stores threat intelligence from external APIs:
- `intel_type` → `keyword` (e.g. `virustotal`, `otx`, `malwarebazaar`)
- `indicator` → `keyword` (the hash, IP, or domain being analyzed)
- `threat_level` → `keyword` (`high`/`low`)
- `raw_data` → `object, enabled: false` (stored but not indexed — saves space for large API payloads)

**`threat-detection-alerts`**
Stores synthesized security alerts:
- `severity` → `keyword` (high/medium/low/critical)
- `message` → `text` (full-text searchable)
- `context` → `object, enabled: false` (unindexed payload)

**`threat-detection-ip-reputation`**
Stores IP reputation from AbuseIPDB + IP-API:
- `ip_address` → `ip` type
- `abuse_confidence` → `integer`
- `is_malicious` → `boolean`
- `country_code`, `isp` for geo analysis

**`threat-detection-cves`**
Stores CVE vulnerability records:
- `cve_id` used as Elasticsearch `_id` → prevents duplicate CVE entries
- `date_published` → `date` with flexible format parsing (ISO + epoch)
- `description` → `text` (full-text searchable)

#### Key class: `ThreatIntelElasticsearch`

- On connect, auto-creates all 5 indices if they don't exist yet
- Falls back to offline mode if Elasticsearch is unreachable

**Indexing methods:**

| Method | Target index |
|--------|-------------|
| `bulk_index_anomalies(df_rows)` | `threat-detection-anomalies` |
| `index_anomaly(event)` | `threat-detection-anomalies` |
| `index_virustotal_result(result)` | `threat-detection-intel` |
| `index_ip_geolocation(result)` | `threat-detection-ip-reputation` |
| `index_ip_abuseipdb(ip, data)` | `threat-detection-ip-reputation` |
| `index_cve(cve)` | `threat-detection-cves` |

**Query methods:**
- `get_recent_anomalies(hours, size)` — last N hours, sorted by anomaly score descending
- `get_malicious_files()` — all VirusTotal entries with `status: malicious`
- `get_threat_summary()` — document count per index (used for dashboard/status)

---

### 5. `src/siem_pipeline.py` — SIEM Orchestrator

The **top-level coordinator**. Composes the other three modules into a complete pipeline. This is the only module that calling code (`anomaly_detection.py`, `run_threat_analysis.py`) needs to import directly.

#### Class: `SIEMPipeline`

Owns one `ThreatEventProducer` and one `ThreatIntelElasticsearch` instance.

**Anomaly path:**
```
process_anomalies(df)
  ├─ for each row → producer.publish_anomaly(record)       [Kafka]
  ├─ es_client.bulk_index_anomalies(records)               [Elasticsearch]
  └─ if any row is High/Critical → producer.publish_alert() [Kafka alert]
```

**Threat intel path:**
```
process_threat_analysis_results(results)
  ├─ process_virustotal_results()
  │    ├─ es_client.index_virustotal_result()              [Elasticsearch]
  │    ├─ producer.publish_threat_intel('virustotal', …)   [Kafka]
  │    └─ if malicious → producer.publish_alert()          [Kafka alert]
  ├─ process_ip_geolocation()
  │    └─ es_client.index_ip_geolocation()                 [Elasticsearch]
  └─ process_cve_data()
       └─ es_client.index_cve()                            [Elasticsearch]
```

**Consumer path (Kafka → Elasticsearch routing):**
```
start_consumer(max_messages)
  └─ ThreatEventConsumer.consume()
       ├─ event_type='anomaly_detected'  → es_client.index_anomaly()
       ├─ event_type='threat_intel'      → dispatched by intel_type
       │    ├─ 'virustotal'              → index_virustotal_result()
       │    ├─ 'ip_geolocation'          → index_ip_geolocation()
       │    └─ 'cve'                     → index_cve()
       └─ event_type='security_alert'   → index_document(INDEX_ALERTS)
```

---

## Full End-to-End Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                            │
│   cybersecurity_attacks.csv (40k records)  6 Threat Intel APIs  │
│   VirusTotal · AbuseIPDB · OTX · CVE CIRCL · MalwareBazaar · IP-API
└────────────┬────────────────────────────────────┬───────────────┘
             │                                    │
             ▼                                    ▼
┌────────────────────────┐          ┌─────────────────────────────┐
│  anomaly_detection.py  │          │  src/data_collector.py      │
│  Isolation Forest      │          │  ThreatDataCollector        │
│  DBSCAN                │          │  collect_daily_threat_intel()│
│  → if_anomalies (df)   │          │  → stores in SQLite         │
└────────────┬───────────┘          └──────────────┬──────────────┘
             │                                     │
             │  publish_anomalies_to_siem()         │  (step in collect_daily)
             │                                     │
             └─────────────┬───────────────────────┘
                           │
                           ▼
             ┌─────────────────────────┐
             │  src/siem_pipeline.py   │
             │  SIEMPipeline           │
             │  process_anomalies()    │
             │  process_threat_*()     │
             └──────┬──────────┬───────┘
                    │          │
          ┌─────────▼──┐   ┌───▼───────────────────────┐
          │   KAFKA     │   │      ELASTICSEARCH        │
          │  3 topics   │   │      5 indices            │
          │             │   │                           │
          │ anomaly-    │   │ threat-detection-anomalies│
          │ detections  │   │ threat-detection-intel    │
          │             │   │ threat-detection-alerts   │
          │ threat-intel│   │ threat-detection-         │
          │             │   │   ip-reputation           │
          │ security-   │   │ threat-detection-cves     │
          │ alerts      │   │                           │
          └──────┬──────┘   └───────────────────────────┘
                 │                       ▲
                 │  start_consumer()     │
                 │  ThreatEventConsumer  │
                 └───────────────────────┘
                   (routes Kafka events
                    back to Elasticsearch)
```

---

## Module Dependency Map

```
setup.py
   └── (loaded by all modules via load_dotenv)

data_collector.py
   └── kafka_pipeline.ThreatEventProducer   (optional, offline-safe)

kafka_pipeline.py
   └── (standalone, no internal deps)

elasticsearch_client.py
   └── (standalone, no internal deps)

siem_pipeline.py
   ├── kafka_pipeline.ThreatEventProducer
   ├── kafka_pipeline.ThreatEventConsumer
   └── elasticsearch_client.ThreatIntelElasticsearch

anomaly_detection.py  (root)
   └── siem_pipeline.SIEMPipeline

run_threat_analysis.py  (root)
   ├── data_collector.ThreatDataCollector
   └── siem_pipeline.SIEMPipeline
```

---

## Design Principles

| Principle | How it's applied |
|-----------|-----------------|
| **Offline-safe** | Both Kafka and Elasticsearch fail silently — existing CSV/SQLite output is never affected |
| **Decoupled** | Producers don't know about Elasticsearch; consumers don't know about ML detection |
| **Typed schema** | ES mappings enforce IP, float, keyword, boolean types — prevents silent data corruption |
| **No duplicate CVEs** | CVE ID used as Elasticsearch `_id` — re-indexing is idempotent |
| **Bulk operations** | Anomalies (up to 4,000 per run) use ES bulk API, not individual index calls |
| **Alert escalation** | High/Critical severity triggers a separate Kafka alert event automatically |

---

## Running the Pipeline

### With Kafka + Elasticsearch (full SIEM mode)

Start services:
```bash
# Kafka (via Docker)
docker run -d -p 9092:9092 apache/kafka:latest

# Elasticsearch
docker run -d -p 9200:9200 -e "discovery.type=single-node" elasticsearch:8.11.0
```

Run detection (publishes to Kafka + indexes to ES automatically):
```bash
python anomaly_detection.py
python run_threat_analysis.py
```

Start the consumer to route any queued Kafka events into Elasticsearch:
```python
from src.siem_pipeline import SIEMPipeline
pipeline = SIEMPipeline()
pipeline.start_consumer(max_messages=1000)
pipeline.print_status()
```

### Without Kafka + Elasticsearch (offline mode)

No changes needed — both scripts run normally and save results to CSV/SQLite as before.
