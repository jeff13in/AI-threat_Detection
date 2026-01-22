# AI Threat Detection System

An AI-powered cybersecurity threat detection system that uses machine learning for anomaly detection and integrates with multiple threat intelligence APIs for comprehensive security analysis.

## Features

- **Machine Learning Anomaly Detection**
  - Isolation Forest algorithm for outlier detection
  - DBSCAN clustering for density-based anomaly identification
  - PCA dimensionality reduction for visualization

- **Threat Intelligence Collection**
  - VirusTotal API (v3) - File/hash reputation analysis
  - AbuseIPDB - IP reputation checking
  - OTX AlienVault - Threat indicators and pulses
  - MalwareBazaar - Malware sample intelligence
  - CVE CIRCL - Latest vulnerability tracking
  - IP-API - Geolocation data

- **Analysis & Reporting**
  - Automated threat analysis pipeline
  - CSV and JSON export formats
  - Visualization charts (attack distribution, anomaly scores)

## Tech Stack

| Category | Technologies |
|----------|-------------|
| **ML/AI** | scikit-learn, TensorFlow, PyTorch |
| **Data Processing** | Pandas, NumPy |
| **Visualization** | Matplotlib, Seaborn, Plotly |
| **Web Framework** | Flask, Dash |
| **Database** | SQLite, PostgreSQL |
| **SIEM Integration** | Elasticsearch, Kafka, Redis |

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/jeff13in/Automated-Pentesting.git
   cd Automated-Pentesting
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and add your API keys (see [API Configuration](#api-configuration))

## Usage

### Run Anomaly Detection
Analyze the cybersecurity attacks dataset using ML algorithms:
```bash
python anomaly_detection.py
```

**Output:**
- `data/cybersecurity_attacks/detected_anomalies.csv` - All detected anomalies
- `data/cybersecurity_attacks/top_100_anomalies.csv` - Top 100 most anomalous records
- Visualization PNG files

### Run Threat Intelligence Analysis
Collect threat data from multiple APIs:
```bash
python run_threat_analysis.py
```

**Output (saved to `results/` folder):**
- `threat_analysis_*.json` - Full analysis results
- `virustotal_results_*.csv` - VirusTotal scan results
- `ip_geolocation_*.csv` - IP location data
- `latest_cves_*.csv` - Recent CVE vulnerabilities

## API Configuration

Get free API keys from these sources and add them to your `.env` file:

| API | Get Key From | Rate Limit |
|-----|--------------|------------|
| VirusTotal | [virustotal.com](https://www.virustotal.com/gui/join-us) | 500/day |
| AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/register) | 1000/day |
| OTX AlienVault | [otx.alienvault.com](https://otx.alienvault.com/) | 10000/hour |
| MalwareBazaar | [auth.abuse.ch](https://auth.abuse.ch/) | Unlimited |

**Note:** IP-API and CVE CIRCL are free and don't require API keys.

## Project Structure

```
Automated-Pentesting/
├── anomaly_detection.py      # Main ML anomaly detection pipeline
├── run_threat_analysis.py    # Threat intelligence collection script
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variables template
├── config/
│   └── config.yaml           # Configuration settings
├── src/
│   ├── data_collector.py     # API integration module
│   └── setup.py              # Environment setup
├── data/
│   └── cybersecurity_attacks/
│       ├── cybersecurity_attacks.csv  # Dataset (40,000 records)
│       ├── detected_anomalies.csv     # Detection results
│       └── *.png                       # Visualization charts
├── results/                  # Analysis output (gitignored)
├── models/                   # Trained models (gitignored)
└── logs/                     # Application logs (gitignored)
```

## Dataset

The system includes a cybersecurity attacks dataset with **40,000 records** and **25 features**:

- Network traffic data (Source/Destination IP, Ports, Protocol)
- Packet information (Length, Type, Traffic Type)
- Security indicators (Anomaly Scores, Malware Indicators)
- Attack classification (Attack Type, Severity Level)
- Response data (Action Taken, Alerts/Warnings)

### Attack Types Distribution
| Attack Type | Percentage |
|-------------|------------|
| DDoS | 33.57% |
| Malware | 33.27% |
| Intrusion | 33.16% |

## Detection Results

The Isolation Forest model detects approximately **10% of records as anomalies** (4,000 out of 40,000), configured with:
- Contamination rate: 0.1
- Number of estimators: 100

## License

This project is for educational and research purposes.

## Disclaimer

This tool is intended for authorized security testing, educational purposes, and defensive security research only. Users are responsible for ensuring compliance with applicable laws and regulations.
