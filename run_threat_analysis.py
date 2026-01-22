"""
Threat Analysis Runner
Collects threat intelligence from APIs and saves results to the results folder
"""

import os
import json
import csv
from datetime import datetime
from dotenv import load_dotenv
import pandas as pd

# Load environment variables
load_dotenv()

from src.data_collector import ThreatDataCollector

def run_analysis():
    print("=" * 70)
    print("           THREAT INTELLIGENCE ANALYSIS")
    print("=" * 70)
    print()

    collector = ThreatDataCollector()
    results = {
        'timestamp': datetime.now().isoformat(),
        'virustotal': [],
        'ip_geolocation': [],
        'cve_data': [],
        'summary': {}
    }

    # ========================================
    # 1. VirusTotal Analysis - Known Malware Hashes
    # ========================================
    print("[1/3] Running VirusTotal Analysis...")
    print("-" * 50)

    # Sample of known malware/test hashes to analyze
    test_hashes = [
        # EICAR test file (standard AV test)
        ('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'EICAR Test File'),
        # WannaCry ransomware sample
        ('ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa', 'WannaCry Sample'),
        # Mirai botnet sample
        ('2e8a4e3d1b0e0c5a4e3c3f3a3e3b3d3c3a3f3e3d3c3b3a3e3f3d3c3b3a3e3f3d', 'Test Hash'),
    ]

    vt_results = []
    for file_hash, description in test_hashes:
        print(f"  Checking: {description}")
        response = collector.check_file_virustotal(file_hash)

        if response.success:
            data = response.data.get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            result = {
                'hash': file_hash,
                'description': description,
                'file_name': data.get('meaningful_name', 'Unknown'),
                'file_type': data.get('type_description', 'Unknown'),
                'file_size': data.get('size', 0),
                'malicious_detections': stats.get('malicious', 0),
                'suspicious_detections': stats.get('suspicious', 0),
                'total_engines': sum(stats.values()),
                'detection_rate': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                'status': 'malicious' if stats.get('malicious', 0) > 0 else 'clean',
                'first_submission': data.get('first_submission_date', 'Unknown'),
                'last_analysis': data.get('last_analysis_date', 'Unknown')
            }
            print(f"    ✅ Detected: {result['detection_rate']} engines flagged as malicious")
        else:
            result = {
                'hash': file_hash,
                'description': description,
                'status': 'not_found' if 'not found' in str(response.error_message).lower() else 'error',
                'error': response.error_message
            }
            print(f"    ❌ {response.error_message}")

        vt_results.append(result)
        results['virustotal'].append(result)

    print()

    # ========================================
    # 2. IP Geolocation Analysis
    # ========================================
    print("[2/3] Running IP Geolocation Analysis...")
    print("-" * 50)

    # Load some IPs from the anomaly detection results if available
    anomaly_file = 'data/cybersecurity_attacks/detected_anomalies.csv'
    sample_ips = []

    if os.path.exists(anomaly_file):
        df = pd.read_csv(anomaly_file)
        if 'Source IP Address' in df.columns:
            sample_ips = df['Source IP Address'].head(10).unique().tolist()
            print(f"  Loaded {len(sample_ips)} IPs from detected anomalies")

    # Add some known IPs for testing
    sample_ips.extend(['8.8.8.8', '1.1.1.1'])
    sample_ips = list(set(sample_ips))[:10]  # Limit to 10 unique IPs

    ip_results = []
    for ip in sample_ips:
        print(f"  Checking: {ip}")
        response = collector.get_ip_geolocation(ip)

        if response.success:
            data = response.data
            result = {
                'ip_address': ip,
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'org': data.get('org', 'Unknown'),
                'as': data.get('as', 'Unknown'),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0),
                'status': 'success'
            }
            print(f"    ✅ {data.get('country', 'Unknown')} - {data.get('city', 'Unknown')} ({data.get('isp', 'Unknown')})")
        else:
            result = {
                'ip_address': ip,
                'status': 'error',
                'error': response.error_message
            }
            print(f"    ❌ {response.error_message}")

        ip_results.append(result)
        results['ip_geolocation'].append(result)

    print()

    # ========================================
    # 3. CVE Analysis
    # ========================================
    print("[3/3] Fetching Latest CVEs...")
    print("-" * 50)

    response = collector.get_latest_cves()

    if response.success:
        cve_list = response.data[:20]  # Get top 20 CVEs
        print(f"  ✅ Retrieved {len(cve_list)} latest CVEs")

        for cve in cve_list[:5]:  # Show first 5
            cve_id = cve.get('cveMetadata', {}).get('cveId', 'Unknown')
            containers = cve.get('containers', {}).get('cna', {})
            title = containers.get('title', 'No title')[:60]
            print(f"    - {cve_id}: {title}...")

        results['cve_data'] = cve_list
    else:
        print(f"  ❌ Failed to fetch CVEs: {response.error_message}")

    print()

    # ========================================
    # Save Results
    # ========================================
    print("=" * 70)
    print("SAVING RESULTS")
    print("=" * 70)

    results_dir = 'results'
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Summary
    results['summary'] = {
        'total_vt_scans': len(vt_results),
        'malicious_files': sum(1 for r in vt_results if r.get('status') == 'malicious'),
        'total_ips_analyzed': len(ip_results),
        'total_cves': len(results['cve_data']),
        'analysis_timestamp': results['timestamp']
    }

    # Save full JSON results
    json_path = f"{results_dir}/threat_analysis_{timestamp}.json"
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"  ✅ Full results: {json_path}")

    # Save VirusTotal results as CSV
    if vt_results:
        vt_csv_path = f"{results_dir}/virustotal_results_{timestamp}.csv"
        vt_df = pd.DataFrame(vt_results)
        vt_df.to_csv(vt_csv_path, index=False)
        print(f"  ✅ VirusTotal CSV: {vt_csv_path}")

    # Save IP geolocation results as CSV
    if ip_results:
        ip_csv_path = f"{results_dir}/ip_geolocation_{timestamp}.csv"
        ip_df = pd.DataFrame(ip_results)
        ip_df.to_csv(ip_csv_path, index=False)
        print(f"  ✅ IP Geolocation CSV: {ip_csv_path}")

    # Save CVE results as CSV
    if results['cve_data']:
        cve_csv_path = f"{results_dir}/latest_cves_{timestamp}.csv"
        cve_simplified = []
        for cve in results['cve_data']:
            cve_meta = cve.get('cveMetadata', {})
            containers = cve.get('containers', {}).get('cna', {})
            descriptions = containers.get('descriptions', [{}])
            desc_text = descriptions[0].get('value', 'No description') if descriptions else 'No description'

            cve_simplified.append({
                'cve_id': cve_meta.get('cveId', 'Unknown'),
                'state': cve_meta.get('state', 'Unknown'),
                'date_published': cve_meta.get('datePublished', 'Unknown'),
                'title': containers.get('title', 'No title'),
                'description': desc_text[:500]
            })
        cve_df = pd.DataFrame(cve_simplified)
        cve_df.to_csv(cve_csv_path, index=False)
        print(f"  ✅ CVE CSV: {cve_csv_path}")

    print()
    print("=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
    print()
    print("Summary:")
    print(f"  - VirusTotal scans: {results['summary']['total_vt_scans']} ({results['summary']['malicious_files']} malicious)")
    print(f"  - IPs analyzed: {results['summary']['total_ips_analyzed']}")
    print(f"  - CVEs retrieved: {results['summary']['total_cves']}")
    print(f"  - Results saved to: {results_dir}/")
    print()

    return results


if __name__ == "__main__":
    run_analysis()
