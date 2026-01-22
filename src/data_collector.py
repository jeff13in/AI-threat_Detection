"""
Data Collector Module for AI Threat Detection System
Collects data from various free security and threat intelligence APIs
"""

import requests
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import os
from dataclasses import dataclass
import hashlib
import sqlite3
from pathlib import Path

@dataclass
class APIResponse:
    """Structure for API responses"""
    source: str
    data: Dict[Any, Any]
    timestamp: datetime
    success: bool
    error_message: Optional[str] = None

class ThreatDataCollector:
    """Main class for collecting threat intelligence data from free APIs"""
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AI-ThreatDetection/1.0'
        })
        
        # Initialize database
        self.db_path = "data/threat_intel.db"
        self._init_database()
        
        # API configurations
        self.apis = {
            'abuseipdb': {
                'base_url': 'https://api.abuseipdb.com/api/v2',
                'rate_limit': 1000,  # requests per day
                'requires_key': True
            },
            'virustotal': {
                'base_url': 'https://www.virustotal.com/api/v3',
                'rate_limit': 500,   # requests per day
                'requires_key': True
            },
            'otx_alienvault': {
                'base_url': 'https://otx.alienvault.com/api/v1',
                'rate_limit': 10000, # requests per hour
                'requires_key': True
            },
            'ip_api': {
                'base_url': 'http://ip-api.com/json',
                'rate_limit': 45,    # requests per minute
                'requires_key': False
            },
            'cve_details': {
                'base_url': 'https://cve.circl.lu/api',
                'rate_limit': None,  # No explicit limit
                'requires_key': False
            },
            'malwarebazaar': {
                'base_url': 'https://mb-api.abuse.ch/api/v1',
                'rate_limit': None,  # No explicit limit
                'requires_key': True  # Now requires Auth-Key from https://auth.abuse.ch/
            }
        }
        
        # Load API keys from environment
        self.api_keys = {
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'otx_alienvault': os.getenv('OTX_API_KEY'),
            'malwarebazaar': os.getenv('MALWAREBAZAAR_API_KEY')
        }

    def _init_database(self):
        """Initialize SQLite database for storing collected data"""
        Path("data").mkdir(exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                request_hash TEXT UNIQUE,
                response_data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                error_message TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                source TEXT NOT NULL,
                threat_level TEXT,
                first_seen DATETIME,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reputation_score INTEGER,
                abuse_confidence INTEGER,
                country_code TEXT,
                is_malicious BOOLEAN,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_data TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def _make_request(self, url: str, headers: Dict = None, params: Dict = None, 
                     timeout: int = 30) -> APIResponse:
        """Make HTTP request with error handling and logging"""
        try:
            response = self.session.get(url, headers=headers, params=params, timeout=timeout)
            
            if response.status_code == 200:
                return APIResponse(
                    source=url.split('/')[2],  # Extract domain
                    data=response.json() if response.content else {},
                    timestamp=datetime.now(),
                    success=True
                )
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                self.logger.error(f"API request failed: {error_msg}")
                return APIResponse(
                    source=url.split('/')[2],
                    data={},
                    timestamp=datetime.now(),
                    success=False,
                    error_message=error_msg
                )
                
        except requests.exceptions.RequestException as e:
            error_msg = f"Request exception: {str(e)}"
            self.logger.error(error_msg)
            return APIResponse(
                source=url.split('/')[2] if '/' in url else 'unknown',
                data={},
                timestamp=datetime.now(),
                success=False,
                error_message=error_msg
            )

    def check_ip_reputation_abuseipdb(self, ip_address: str) -> APIResponse:
        """Check IP reputation using AbuseIPDB"""
        if not self.api_keys['abuseipdb']:
            return APIResponse('abuseipdb', {}, datetime.now(), False, 'API key not found')
        
        url = f"{self.apis['abuseipdb']['base_url']}/check"
        headers = {
            'Key': self.api_keys['abuseipdb'],
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        response = self._make_request(url, headers=headers, params=params)
        
        # Store in database
        if response.success:
            self._store_ip_reputation(ip_address, response.data, 'abuseipdb')
        
        return response

    def get_ip_geolocation(self, ip_address: str) -> APIResponse:
        """Get IP geolocation data using IP-API (free, no key required)"""
        url = f"{self.apis['ip_api']['base_url']}/{ip_address}"
        
        response = self._make_request(url)
        
        # Add delay to respect rate limits (45 requests per minute)
        time.sleep(1.5)
        
        return response

    def check_file_virustotal(self, file_hash: str) -> APIResponse:
        """Check file reputation using VirusTotal API v3"""
        if not self.api_keys['virustotal']:
            return APIResponse('virustotal', {}, datetime.now(), False, 'API key not found')

        url = f"{self.apis['virustotal']['base_url']}/files/{file_hash}"
        headers = {
            'x-apikey': self.api_keys['virustotal']
        }

        response = self._make_request(url, headers=headers)

        # VirusTotal has strict rate limits - add delay
        time.sleep(15)  # 4 requests per minute for free tier

        return response

    def get_otx_indicators(self, indicator_type: str = 'IPv4', indicator_value: str = None) -> APIResponse:
        """Get threat indicators from OTX AlienVault

        Args:
            indicator_type: Type of indicator (IPv4, IPv6, domain, hostname, url, FileHash-MD5, FileHash-SHA1, FileHash-SHA256)
            indicator_value: The actual indicator value to look up (e.g., IP address, domain)

        If no indicator_value provided, returns subscribed pulses instead.
        """
        if not self.api_keys['otx_alienvault']:
            return APIResponse('otx', {}, datetime.now(), False, 'API key not found')

        headers = {
            'X-OTX-API-KEY': self.api_keys['otx_alienvault']
        }

        if indicator_value:
            # Get details for a specific indicator
            url = f"{self.apis['otx_alienvault']['base_url']}/indicators/{indicator_type}/{indicator_value}/general"
        else:
            # Get subscribed pulses (threat intel feeds)
            url = f"{self.apis['otx_alienvault']['base_url']}/pulses/subscribed"

        response = self._make_request(url, headers=headers)

        return response

    def get_latest_cves(self, limit: int = 10) -> APIResponse:
        """Get latest CVE entries (no API key required)"""
        url = f"{self.apis['cve_details']['base_url']}/last"
        
        response = self._make_request(url)
        
        return response

    def get_malware_samples(self, limit: int = 100) -> APIResponse:
        """Get recent malware samples from MalwareBazaar (requires Auth-Key)"""
        if not self.api_keys.get('malwarebazaar'):
            return APIResponse('malwarebazaar', {}, datetime.now(), False,
                             'API key not found. Get free key at https://auth.abuse.ch/')

        url = f"{self.apis['malwarebazaar']['base_url']}/"
        headers = {
            'Auth-Key': self.api_keys['malwarebazaar']
        }
        data = {
            'query': 'get_recent',
            'selector': limit
        }

        try:
            response = self.session.post(url, headers=headers, data=data, timeout=30)

            if response.status_code == 200:
                return APIResponse(
                    source='malwarebazaar',
                    data=response.json() if response.content else {},
                    timestamp=datetime.now(),
                    success=True
                )
            else:
                error_msg = f"HTTP {response.status_code}: {response.text}"
                return APIResponse(
                    source='malwarebazaar',
                    data={},
                    timestamp=datetime.now(),
                    success=False,
                    error_message=error_msg
                )

        except Exception as e:
            return APIResponse(
                source='malwarebazaar',
                data={},
                timestamp=datetime.now(),
                success=False,
                error_message=str(e)
            )

    def _store_ip_reputation(self, ip_address: str, data: Dict, source: str):
        """Store IP reputation data in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO ip_reputation 
                (ip_address, reputation_score, abuse_confidence, country_code, 
                 is_malicious, source_data)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                ip_address,
                data.get('abuseConfidencePercentage', 0),
                data.get('abuseConfidencePercentage', 0),
                data.get('countryCode', ''),
                data.get('abuseConfidencePercentage', 0) > 50,
                json.dumps(data)
            ))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error storing IP reputation: {e}")
        finally:
            conn.close()

    def store_api_response(self, response: APIResponse, endpoint: str):
        """Store API response in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Create hash for deduplication
            request_hash = hashlib.md5(f"{response.source}_{endpoint}_{datetime.now().date()}".encode()).hexdigest()
            
            cursor.execute('''
                INSERT OR REPLACE INTO api_responses 
                (source, endpoint, request_hash, response_data, success, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                response.source,
                endpoint,
                request_hash,
                json.dumps(response.data) if response.success else None,
                response.success,
                response.error_message
            ))
            conn.commit()
        except Exception as e:
            self.logger.error(f"Error storing API response: {e}")
        finally:
            conn.close()

    def collect_daily_threat_intel(self) -> List[APIResponse]:
        """Collect daily threat intelligence from all available sources"""
        responses = []
        
        self.logger.info("Starting daily threat intelligence collection")
        
        # Sample IPs for reputation checking (you can modify this list)
        sample_ips = [
            '8.8.8.8',  # Google DNS
            '1.1.1.1',  # Cloudflare DNS
            '185.220.100.240',  # Known Tor exit node
            '192.168.1.1'  # Private IP (for testing)
        ]
        
        # Check IP reputations
        for ip in sample_ips:
            # AbuseIPDB check
            response = self.check_ip_reputation_abuseipdb(ip)
            responses.append(response)
            self.store_api_response(response, f"check_ip/{ip}")
            
            # Geolocation data
            geo_response = self.get_ip_geolocation(ip)
            responses.append(geo_response)
            self.store_api_response(geo_response, f"geolocation/{ip}")
        
        # Get latest CVEs
        cve_response = self.get_latest_cves()
        responses.append(cve_response)
        self.store_api_response(cve_response, "latest_cves")
        
        # Get malware samples
        malware_response = self.get_malware_samples()
        responses.append(malware_response)
        self.store_api_response(malware_response, "recent_malware")
        
        # Get OTX indicators
        otx_response = self.get_otx_indicators()
        responses.append(otx_response)
        self.store_api_response(otx_response, "otx_indicators")
        
        self.logger.info(f"Completed threat intelligence collection. Processed {len(responses)} API calls")
        
        return responses

    def get_stored_data(self, source: str = None, days_back: int = 7) -> List[Dict]:
        """Retrieve stored data from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            if source:
                cursor.execute('''
                    SELECT * FROM api_responses 
                    WHERE source = ? AND timestamp >= datetime('now', '-{} days')
                    ORDER BY timestamp DESC
                '''.format(days_back), (source,))
            else:
                cursor.execute('''
                    SELECT * FROM api_responses 
                    WHERE timestamp >= datetime('now', '-{} days')
                    ORDER BY timestamp DESC
                '''.format(days_back))
            
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
            
        except Exception as e:
            self.logger.error(f"Error retrieving stored data: {e}")
            return []
        finally:
            conn.close()


if __name__ == "__main__":
    # Example usage
    collector = ThreatDataCollector()
    
    # Collect threat intelligence
    responses = collector.collect_daily_threat_intel()
    
    # Print summary
    successful = sum(1 for r in responses if r.success)
    failed = len(responses) - successful
    
    print(f"Collection Summary:")
    print(f"- Successful API calls: {successful}")
    print(f"- Failed API calls: {failed}")
    print(f"- Total responses collected: {len(responses)}")
