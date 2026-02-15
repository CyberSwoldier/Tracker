"""
Threat Intelligence Data Collectors
Pulls from 6 open-source security feeds
"""

import requests
import feedparser
import json
import re
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import time

class ThreatDataCollector:
    """Base collector class"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatTracker/1.0'
        })
        
    def extract_location(self, text):
        """Extract country/location mentions from text"""
        countries = [
            'United States', 'USA', 'US', 'China', 'Russia', 'North Korea', 'Iran',
            'Ukraine', 'Israel', 'India', 'Pakistan', 'UK', 'United Kingdom',
            'Germany', 'France', 'Japan', 'South Korea', 'Taiwan', 'Vietnam',
            'Brazil', 'Mexico', 'Canada', 'Australia', 'Turkey', 'Saudi Arabia'
        ]
        
        found_locations = []
        text_lower = text.lower()
        
        for country in countries:
            if country.lower() in text_lower:
                found_locations.append(country)
        
        return found_locations if found_locations else ['Global']

class CISAFeedCollector(ThreatDataCollector):
    """CISA (Cybersecurity & Infrastructure Security Agency) Alerts"""
    
    def collect(self):
        """Collect from CISA alerts RSS feed"""
        threats = []
        
        try:
            feed = feedparser.parse('https://www.cisa.gov/news.xml')
            
            for entry in feed.entries[:10]:  # Last 10 entries
                threat = {
                    'source': 'CISA',
                    'title': entry.title,
                    'description': entry.get('summary', entry.title),
                    'url': entry.link,
                    'published': entry.get('published', datetime.now().isoformat()),
                    'severity': self._assess_severity(entry.title + ' ' + entry.get('summary', '')),
                    'locations': self.extract_location(entry.title + ' ' + entry.get('summary', '')),
                    'threat_type': 'Cyber',
                    'raw_data': entry
                }
                threats.append(threat)
                
        except Exception as e:
            print(f"[!] Error collecting from CISA: {e}")
            
        return threats
    
    def _assess_severity(self, text):
        """Assess severity based on keywords"""
        text_lower = text.lower()
        if any(word in text_lower for word in ['critical', 'emergency', 'severe', 'zero-day', 'actively exploited']):
            return 'CRITICAL'
        elif any(word in text_lower for word in ['high', 'important', 'significant', 'ransomware']):
            return 'HIGH'
        elif any(word in text_lower for word in ['medium', 'moderate', 'vulnerability']):
            return 'MEDIUM'
        else:
            return 'LOW'

class CVEFeedCollector(ThreatDataCollector):
    """CVE (Common Vulnerabilities and Exposures) Recent Feed"""
    
    def collect(self):
        """Collect recent CVEs from NVD"""
        threats = []
        
        try:
            # Using NIST NVD RSS feed for recent CVEs
            feed = feedparser.parse('https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml')
            
            for entry in feed.entries[:15]:
                # Extract CVE ID
                cve_match = re.search(r'CVE-\d{4}-\d+', entry.title)
                cve_id = cve_match.group(0) if cve_match else 'Unknown'
                
                threat = {
                    'source': 'NVD-CVE',
                    'title': entry.title,
                    'description': entry.get('summary', entry.title),
                    'url': entry.link,
                    'published': entry.get('published', datetime.now().isoformat()),
                    'severity': self._extract_severity(entry.get('summary', '')),
                    'locations': ['Global'],
                    'threat_type': 'Vulnerability',
                    'cve_id': cve_id,
                    'raw_data': entry
                }
                threats.append(threat)
                
        except Exception as e:
            print(f"[!] Error collecting from CVE feed: {e}")
            
        return threats
    
    def _extract_severity(self, text):
        """Extract CVSS severity"""
        if 'CRITICAL' in text.upper() or '9.' in text or '10.0' in text:
            return 'CRITICAL'
        elif 'HIGH' in text.upper() or '7.' in text or '8.' in text:
            return 'HIGH'
        elif 'MEDIUM' in text.upper() or '4.' in text or '5.' in text or '6.' in text:
            return 'MEDIUM'
        else:
            return 'LOW'

class ThreatFoxCollector(ThreatDataCollector):
    """ThreatFox - IOC database by abuse.ch"""
    
    def collect(self):
        """Collect from ThreatFox API"""
        threats = []
        
        try:
            # Get recent IOCs from ThreatFox
            url = 'https://threatfox-api.abuse.ch/api/v1/'
            data = {
                'query': 'get_iocs',
                'days': 1
            }
            
            response = self.session.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('query_status') == 'ok':
                    iocs = result.get('data', [])[:10]
                    
                    for ioc in iocs:
                        threat = {
                            'source': 'ThreatFox',
                            'title': f"{ioc.get('malware', 'Unknown')} - {ioc.get('ioc_type', 'IOC')}",
                            'description': f"IOC: {ioc.get('ioc', 'N/A')} | Threat: {ioc.get('threat_type', 'Unknown')}",
                            'url': f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}",
                            'published': ioc.get('first_seen', datetime.now().isoformat()),
                            'severity': 'HIGH',
                            'locations': self.extract_location(str(ioc)),
                            'threat_type': 'Malware/IOC',
                            'ioc': ioc.get('ioc'),
                            'malware': ioc.get('malware'),
                            'raw_data': ioc
                        }
                        threats.append(threat)
                        
        except Exception as e:
            print(f"[!] Error collecting from ThreatFox: {e}")
            
        return threats

class AlienVaultOTXCollector(ThreatDataCollector):
    """AlienVault OTX Pulses"""
    
    def collect(self):
        """Collect from AlienVault OTX public pulses"""
        threats = []
        
        try:
            # Public pulses endpoint
            url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
            
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('results', [])[:10]
                
                for pulse in pulses:
                    threat = {
                        'source': 'AlienVault OTX',
                        'title': pulse.get('name', 'Unknown Threat'),
                        'description': pulse.get('description', 'No description')[:500],
                        'url': f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                        'published': pulse.get('created', datetime.now().isoformat()),
                        'severity': self._map_tlp_to_severity(pulse.get('TLP', 'white')),
                        'locations': pulse.get('targeted_countries', ['Global']),
                        'threat_type': 'Intelligence',
                        'tags': pulse.get('tags', []),
                        'raw_data': pulse
                    }
                    threats.append(threat)
                    
        except Exception as e:
            print(f"[!] Error collecting from AlienVault OTX: {e}")
            
        return threats
    
    def _map_tlp_to_severity(self, tlp):
        """Map TLP to severity"""
        mapping = {
            'red': 'CRITICAL',
            'amber': 'HIGH',
            'green': 'MEDIUM',
            'white': 'LOW'
        }
        return mapping.get(tlp.lower(), 'MEDIUM')

class URLHausFeedCollector(ThreatDataCollector):
    """URLhaus - Malicious URL sharing by abuse.ch"""
    
    def collect(self):
        """Collect from URLhaus recent URLs"""
        threats = []
        
        try:
            url = 'https://urlhaus-api.abuse.ch/v1/urls/recent/'
            
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                urls = data.get('urls', [])[:10]
                
                for url_data in urls:
                    threat = {
                        'source': 'URLhaus',
                        'title': f"Malicious URL - {url_data.get('threat', 'Unknown')}",
                        'description': f"URL: {url_data.get('url', 'N/A')} | Status: {url_data.get('url_status', 'Unknown')}",
                        'url': f"https://urlhaus.abuse.ch/url/{url_data.get('id', '')}",
                        'published': url_data.get('dateadded', datetime.now().isoformat()),
                        'severity': 'HIGH' if url_data.get('url_status') == 'online' else 'MEDIUM',
                        'locations': self.extract_location(url_data.get('host', '')),
                        'threat_type': 'Malicious URL',
                        'malware': url_data.get('threat'),
                        'raw_data': url_data
                    }
                    threats.append(threat)
                    
        except Exception as e:
            print(f"[!] Error collecting from URLhaus: {e}")
            
        return threats

class TheHackerNewsCollector(ThreatDataCollector):
    """The Hacker News - Security news feed"""
    
    def collect(self):
        """Collect from The Hacker News RSS"""
        threats = []
        
        try:
            feed = feedparser.parse('https://feeds.feedburner.com/TheHackersNews')
            
            for entry in feed.entries[:10]:
                threat = {
                    'source': 'The Hacker News',
                    'title': entry.title,
                    'description': entry.get('summary', entry.title)[:500],
                    'url': entry.link,
                    'published': entry.get('published', datetime.now().isoformat()),
                    'severity': self._assess_news_severity(entry.title + ' ' + entry.get('summary', '')),
                    'locations': self.extract_location(entry.title + ' ' + entry.get('summary', '')),
                    'threat_type': 'News/Intelligence',
                    'raw_data': entry
                }
                threats.append(threat)
                
        except Exception as e:
            print(f"[!] Error collecting from The Hacker News: {e}")
            
        return threats
    
    def _assess_news_severity(self, text):
        """Assess severity from news content"""
        text_lower = text.lower()
        if any(word in text_lower for word in ['zero-day', 'critical vulnerability', 'data breach', 'ransomware attack', 'nation-state']):
            return 'CRITICAL'
        elif any(word in text_lower for word in ['vulnerability', 'malware', 'exploit', 'attack', 'breach']):
            return 'HIGH'
        elif any(word in text_lower for word in ['security', 'threat', 'warning']):
            return 'MEDIUM'
        else:
            return 'LOW'

def collect_all_threats():
    """Collect threats from all sources"""
    print("[+] Starting threat intelligence collection...")
    
    collectors = [
        ('CISA Alerts', CISAFeedCollector()),
        ('CVE/NVD Feed', CVEFeedCollector()),
        ('ThreatFox IOCs', ThreatFoxCollector()),
        ('AlienVault OTX', AlienVaultOTXCollector()),
        ('URLhaus', URLHausFeedCollector()),
        ('The Hacker News', TheHackerNewsCollector())
    ]
    
    all_threats = []
    
    for name, collector in collectors:
        print(f"[*] Collecting from {name}...")
        try:
            threats = collector.collect()
            all_threats.extend(threats)
            print(f"    ✓ Collected {len(threats)} threats from {name}")
            time.sleep(1)  # Be nice to APIs
        except Exception as e:
            print(f"    ✗ Failed to collect from {name}: {e}")
    
    print(f"\n[+] Total threats collected: {len(all_threats)}")
    return all_threats
