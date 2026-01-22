# AI Threat Detection System - Tech Stack Analysis

## 1. Project Structure & Folder Organization

```
/Users/jeffinsam/ai-threat-detection/
├── src/                              # Source code modules
│   ├── data_collector.py            # Threat intelligence data collection
│   └── setup.py                     # Environment configuration
├── config/                          # Configuration files
│   └── config.yaml                  # YAML configuration
├── data/                            # Data directory
│   └── cybersecurity_attacks/       # Dataset (17.8 MB CSV)
│       ├── cybersecurity_attacks.csv # 40,000 records with 25 metrics
│       ├── detected_anomalies.csv   # Detected anomalies output
│       ├── top_100_anomalies.csv    # Top 100 anomalies
│       └── [PNG visualizations]     # Generated analysis plots
├── models/                          # Trained models storage (empty)
├── dashboard/                       # Dashboard components (empty)
├── notebooks/                       # Jupyter notebooks (empty)
├── logs/                            # Application logs
├── anomaly_detection.py             # Main anomaly detection pipeline
├── requirements.txt                 # Python dependencies
├── .env                             # Environment variables
└── venv/                            # Python virtual environment
```

---

## 2. Frontend Technology Stack

**Note:** This is a Python-based application with minimal frontend components.

### Existing Frontend Stack:
| Technology | Version | Purpose |
|------------|---------|---------|
| Dash | 2.14.2 | Python-based interactive web dashboard framework |
| Dash Bootstrap Components | 1.5.0 | UI components library for Dash |
| Plotly | 5.17.0 | Interactive visualization library |

### Frontend Status:
- **Dashboard folder**: Currently empty (placeholder for future implementation)
- **No HTML/JavaScript/React/Vue**: Pure Python-based frontend using Dash
- **Visualization**: Matplotlib and Seaborn for static charts, Plotly for interactive visualizations

---

## 3. Backend Technology Stack

### Core Backend Framework
| Technology | Version | Purpose |
|------------|---------|---------|
| Flask | 3.0.0 | Lightweight Python web framework |
| Flask-SocketIO | 5.3.6 | WebSocket support for real-time communication |

### Data Processing & Machine Learning
| Technology | Version | Purpose |
|------------|---------|---------|
| Pandas | 2.1.4 | Data manipulation and analysis |
| NumPy | 1.24.3 | Numerical computing |
| Scikit-learn | 1.3.2 | Machine learning algorithms |
| TensorFlow | 2.15.0 | Deep learning framework |
| PyTorch | 2.1.0 | Deep learning framework |
| Imbalanced-learn | 0.11.0 | Handling imbalanced datasets |

### Network & Security Analysis
| Technology | Version | Purpose |
|------------|---------|---------|
| Scapy | 2.5.0 | Packet manipulation and analysis |
| Netaddr | 0.9.0 | Network address manipulation |
| Pyshark | 0.6 | Packet capture wrapper |

### SIEM & Integration Stack
| Technology | Version | Purpose |
|------------|---------|---------|
| Elasticsearch | 8.11.0 | Distributed search and analytics engine |
| Kafka-python | 2.0.2 | Apache Kafka client for event streaming |
| Redis | 5.0.1 | In-memory data store |

### Database
| Technology | Purpose |
|------------|---------|
| SQLite | Primary data storage for threat intelligence |
| PostgreSQL | Secondary database option (configured via .env) |

### Data Visualization
| Technology | Version | Purpose |
|------------|---------|---------|
| Matplotlib | 3.7.1 | Static 2D plotting |
| Seaborn | 0.12.2 | Statistical data visualization |
| Plotly | 5.17.0 | Interactive visualizations |

### Monitoring & Logging
| Technology | Version | Purpose |
|------------|---------|---------|
| Prometheus-client | 0.19.0 | Prometheus metrics exporter |
| python-json-logger | 2.0.7 | JSON-formatted logging |

### Utility Libraries
| Technology | Version | Purpose |
|------------|---------|---------|
| PyYAML | 6.0.1 | YAML parsing for configuration |
| python-dotenv | 1.0.0 | Environment variable management |
| Requests | 2.31.0 | HTTP client library |
| Schedule | 1.2.0 | Task scheduling |
| Joblib | 1.3.2 | Serialization and parallel processing |

---

## 4. Configuration

### Environment Variables (.env)
```
SIEM Integration:
  - ELASTICSEARCH_URL (localhost:9200)
  - KAFKA_URL (localhost:9092)
  - REDIS_URL (redis://localhost:6379)

Database:
  - DB_HOST, DB_PORT, DB_NAME
  - PostgreSQL credentials
  - Database name: threat_detection

API Keys:
  - VIRUSTOTAL_API_KEY
  - SHODAN_API_KEY

Email/Alerting:
  - SMTP_SERVER (smtp.gmail.com)
  - SMTP_PORT (587)

Security:
  - SECRET_KEY (Flask session secret)
  - JWT_SECRET (JSON Web Token secret)

ML Configuration:
  - MODEL_UPDATE_INTERVAL (3600s)
  - BATCH_SIZE (1000)
  - DETECTION_THRESHOLD (0.7)
```

### YAML Configuration (config/config.yaml)

**Model Configuration:**
- **Isolation Forest**: contamination=0.1, 100 estimators
- **LSTM Autoencoder**: sequence_length=50, encoding_dim=32, epochs=100
- **Ensemble**: Soft voting with multiple models

**Detection Thresholds:**
- Anomaly score: 0.7
- Confidence level: 0.85
- Severity levels: low (0.3), medium (0.6), high (0.8), critical (0.9)

---

## 5. External APIs Integrated

| API | Key Required | Rate Limit | Purpose |
|-----|--------------|-----------|---------|
| AbuseIPDB | Yes | 1000/day | IP reputation checking |
| VirusTotal | Yes | 500/day | File/URL reputation |
| OTX AlienVault | Yes | 10000/hour | Threat indicators |
| IP-API | No | 45/min | Geolocation data |
| CVE Details | No | Unlimited | Latest CVE information |
| MalwareBazaar | No | Unlimited | Recent malware samples |

---

## 6. Architecture Patterns

### Core Architecture: Data Pipeline + ML Ensemble

```
Raw Cybersecurity Data (40,000 records)
           ↓
Feature Engineering (25 metrics → engineered features)
           ↓
Multiple Anomaly Detection Models (Ensemble):
  ├── Isolation Forest (tree-based)
  ├── LSTM Autoencoder (deep learning)
  ├── One-Class SVM (kernel-based)
  └── DBSCAN (density-based clustering)
           ↓
Soft Voting Ensemble (confidence aggregation)
           ↓
Alert Generation & SIEM Integration
           ↓
Dashboard Visualization & Automated Response
```

### Database Schema (SQLite)
```sql
api_responses:
  - id, source, endpoint, request_hash, response_data
  - timestamp, success, error_message

threat_indicators:
  - id, indicator_type, indicator_value, source
  - threat_level, first_seen, last_updated, metadata

ip_reputation:
  - id, ip_address, reputation_score, abuse_confidence
  - country_code, is_malicious, last_updated, source_data
```

### Severity-Based Response Actions
| Severity Level | Score | Actions |
|---------------|-------|---------|
| Critical | 0.9+ | Isolate host + block IP + email |
| High | 0.8+ | Block IP + email |
| Medium | 0.6+ | Block IP |
| Low | 0.3+ | Email alert only |

---

## 7. Complete Dependencies Summary

**Total Dependencies**: 46 packages

| Category | Count | Packages |
|----------|-------|----------|
| Data Science/ML | 9 | pandas, numpy, scikit-learn, tensorflow, torch, seaborn, matplotlib, plotly, imbalanced-learn |
| Web/API | 3 | flask, flask-socketio, requests |
| SIEM/Integration | 3 | elasticsearch, kafka-python, redis |
| Network Analysis | 3 | scapy, netaddr, pyshark |
| Config/Logging | 5 | pyyaml, python-dotenv, python-json-logger, prometheus-client, schedule |
| Development | 4 | jupyter, pytest, black, flake8 |
| Utilities | 2 | joblib, requests |

---

## 8. Project Status

### Fully Implemented
- Anomaly detection pipeline
- Data collection framework
- Configuration system

### Partial Implementation
- SIEM integration (configured but not fully integrated)

### Placeholder/Empty
- Dashboard directory
- Notebooks directory
- Models directory

---

## 9. Technology Stack Summary

| Layer | Technology | Version |
|-------|-----------|---------|
| **ML/AI** | scikit-learn | 1.3.2 |
| **ML/AI** | TensorFlow | 2.15.0 |
| **ML/AI** | PyTorch | 2.1.0 |
| **Data Processing** | Pandas | 2.1.4 |
| **Visualization** | Matplotlib/Seaborn/Plotly | 3.7.1/0.12.2/5.17.0 |
| **Web Backend** | Flask | 3.0.0 |
| **Web Real-time** | Flask-SocketIO | 5.3.6 |
| **Web Frontend** | Dash | 2.14.2 |
| **Security** | Scapy | 2.5.0 |
| **Message Queue** | Kafka | 2.0.2 |
| **Search Engine** | Elasticsearch | 8.11.0 |
| **Cache** | Redis | 5.0.1 |
| **Database** | SQLite/PostgreSQL | built-in |
| **Config** | PyYAML | 6.0.1 |
| **Monitoring** | Prometheus-client | 0.19.0 |

---

## Summary

This **AI Threat Detection System** is a Python-based, ML-driven security analytics platform designed for network anomaly detection with enterprise SIEM integration capabilities. It uses an ensemble machine learning approach combining Isolation Forest, LSTM Autoencoders, One-Class SVM, and DBSCAN for comprehensive threat detection, along with threat intelligence collection from multiple external APIs.
