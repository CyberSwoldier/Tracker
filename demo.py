#!/usr/bin/env python3
"""
Demo version with sample threat data
Demonstrates all functionality without requiring external API access
"""

import sys
import os
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import ThreatAnalyzer
from visualizer import ThreatVisualizer
from colorama import Fore, Style, init

init(autoreset=True)

def generate_sample_threats():
    """Generate sample threat data for demonstration"""
    
    base_time = datetime.now()
    
    sample_threats = [
        {
            'source': 'CISA',
            'title': 'Critical Vulnerability in Cisco IOS XE Software',
            'description': 'CISA has identified a critical zero-day vulnerability in Cisco IOS XE that is being actively exploited. Attackers are using this vulnerability to gain initial access to enterprise networks and deploy ransomware.',
            'url': 'https://www.cisa.gov/news-events/alerts/2024/example',
            'published': (base_time - timedelta(hours=2)).isoformat(),
            'severity': 'CRITICAL',
            'locations': ['Global', 'United States'],
            'threat_type': 'Vulnerability'
        },
        {
            'source': 'NVD-CVE',
            'title': 'CVE-2024-12345 - Remote Code Execution in Apache Struts',
            'description': 'Remote code execution vulnerability in Apache Struts framework allowing attackers to execute arbitrary commands on affected systems. CVSS Score: 9.8',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
            'published': (base_time - timedelta(hours=5)).isoformat(),
            'severity': 'CRITICAL',
            'locations': ['Global'],
            'threat_type': 'Vulnerability',
            'cve_id': 'CVE-2024-12345'
        },
        {
            'source': 'ThreatFox',
            'title': 'AsyncRAT - Malicious URL',
            'description': 'IOC: malicious-domain.com | Threat: malware_download | AsyncRAT backdoor being distributed via phishing campaigns',
            'url': 'https://threatfox.abuse.ch/ioc/12345',
            'published': (base_time - timedelta(hours=3)).isoformat(),
            'severity': 'HIGH',
            'locations': ['United States', 'United Kingdom', 'Germany'],
            'threat_type': 'Malware/IOC',
            'ioc': 'malicious-domain.com',
            'malware': 'AsyncRAT'
        },
        {
            'source': 'AlienVault OTX',
            'title': 'APT28 Infrastructure Targeting Government Networks',
            'description': 'Russian APT28 (Fancy Bear) observed deploying new infrastructure for spear phishing campaigns targeting government and military organizations. Uses obfuscated PowerShell scripts and stolen credentials.',
            'url': 'https://otx.alienvault.com/pulse/abc123',
            'published': (base_time - timedelta(hours=6)).isoformat(),
            'severity': 'HIGH',
            'locations': ['Ukraine', 'United States', 'United Kingdom'],
            'threat_type': 'Intelligence',
            'tags': ['apt28', 'fancy bear', 'phishing', 'government']
        },
        {
            'source': 'URLhaus',
            'title': 'Malicious URL - Emotet Banking Trojan',
            'description': 'URL: hxxp://compromised-site[.]com/payload.exe | Status: online | Emotet banking trojan distribution',
            'url': 'https://urlhaus.abuse.ch/url/456789',
            'published': (base_time - timedelta(hours=4)).isoformat(),
            'severity': 'HIGH',
            'locations': ['Global'],
            'threat_type': 'Malicious URL',
            'malware': 'Emotet'
        },
        {
            'source': 'The Hacker News',
            'title': 'Lazarus Group Launches New Ransomware Campaign Against Cryptocurrency Exchanges',
            'description': 'North Korean Lazarus Group has been identified launching sophisticated ransomware attacks against cryptocurrency exchanges. The campaign uses social engineering and supply chain attacks to gain initial access.',
            'url': 'https://thehackernews.com/2024/example',
            'published': (base_time - timedelta(hours=8)).isoformat(),
            'severity': 'CRITICAL',
            'locations': ['South Korea', 'Japan', 'United States'],
            'threat_type': 'News/Intelligence'
        },
        {
            'source': 'CISA',
            'title': 'Widespread Brute Force Attacks Against RDP Services',
            'description': 'CISA warns of widespread brute force and password spray attacks targeting Remote Desktop Protocol (RDP) services. Attackers are attempting to gain valid credentials for lateral movement.',
            'url': 'https://www.cisa.gov/news-events/alerts/2024/rdp',
            'published': (base_time - timedelta(hours=12)).isoformat(),
            'severity': 'HIGH',
            'locations': ['Global', 'United States'],
            'threat_type': 'Cyber'
        },
        {
            'source': 'NVD-CVE',
            'title': 'CVE-2024-54321 - SQL Injection in WordPress Plugin',
            'description': 'SQL injection vulnerability in popular WordPress plugin affecting 100,000+ sites. Allows attackers to extract database contents including user credentials. CVSS Score: 7.5',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-54321',
            'published': (base_time - timedelta(hours=10)).isoformat(),
            'severity': 'HIGH',
            'locations': ['Global'],
            'threat_type': 'Vulnerability',
            'cve_id': 'CVE-2024-54321'
        },
        {
            'source': 'The Hacker News',
            'title': 'APT29 Cozy Bear Uses New Malware for Espionage Against Think Tanks',
            'description': 'Russian APT29 (Cozy Bear) discovered using novel malware variants in espionage campaigns targeting policy think tanks and research organizations. The malware uses encrypted C2 communications.',
            'url': 'https://thehackernews.com/2024/apt29',
            'published': (base_time - timedelta(hours=15)).isoformat(),
            'severity': 'HIGH',
            'locations': ['United States', 'United Kingdom', 'Germany'],
            'threat_type': 'News/Intelligence'
        },
        {
            'source': 'ThreatFox',
            'title': 'Cobalt Strike - Command and Control Server',
            'description': 'IOC: 192.168.1.100:443 | Threat: botnet_cc | Cobalt Strike C2 server used in recent ransomware attacks',
            'url': 'https://threatfox.abuse.ch/ioc/789012',
            'published': (base_time - timedelta(hours=7)).isoformat(),
            'severity': 'HIGH',
            'locations': ['Russia', 'China'],
            'threat_type': 'Malware/IOC',
            'ioc': '192.168.1.100',
            'malware': 'Cobalt Strike'
        },
        {
            'source': 'CISA',
            'title': 'FIN7 Cybercrime Group Targeting Retail and Hospitality Sectors',
            'description': 'FIN7 (Carbanak) observed targeting retail and hospitality sectors with credential dumping and point-of-sale malware. Group uses spear phishing with malicious documents.',
            'url': 'https://www.cisa.gov/news-events/alerts/2024/fin7',
            'published': (base_time - timedelta(hours=18)).isoformat(),
            'severity': 'HIGH',
            'locations': ['United States', 'United Kingdom'],
            'threat_type': 'Cyber'
        },
        {
            'source': 'AlienVault OTX',
            'title': 'Sandworm Team Scanning Critical Infrastructure for Vulnerabilities',
            'description': 'Russian Sandworm team (Voodoo Bear) identified conducting reconnaissance and vulnerability scanning against energy sector and critical infrastructure systems.',
            'url': 'https://otx.alienvault.com/pulse/def456',
            'published': (base_time - timedelta(hours=20)).isoformat(),
            'severity': 'CRITICAL',
            'locations': ['Ukraine', 'United States', 'Germany'],
            'threat_type': 'Intelligence',
            'tags': ['sandworm', 'critical infrastructure', 'energy', 'scanning']
        },
        {
            'source': 'NVD-CVE',
            'title': 'CVE-2024-99999 - Authentication Bypass in VPN Software',
            'description': 'Critical authentication bypass in enterprise VPN software allowing unauthorized access. Actively exploited in the wild. CVSS Score: 9.1',
            'url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-99999',
            'published': (base_time - timedelta(hours=1)).isoformat(),
            'severity': 'CRITICAL',
            'locations': ['Global'],
            'threat_type': 'Vulnerability',
            'cve_id': 'CVE-2024-99999'
        },
        {
            'source': 'The Hacker News',
            'title': 'New Phishing Campaign Targets Financial Services with Fake Login Pages',
            'description': 'Large-scale phishing campaign targeting financial services employees with credential harvesting pages. Campaign uses social engineering and spoofed domains.',
            'url': 'https://thehackernews.com/2024/phishing',
            'published': (base_time - timedelta(hours=9)).isoformat(),
            'severity': 'MEDIUM',
            'locations': ['Global', 'United States', 'United Kingdom'],
            'threat_type': 'News/Intelligence'
        },
        {
            'source': 'URLhaus',
            'title': 'Malicious URL - Qakbot Trojan Distribution',
            'description': 'URL: hxxp://evil-site[.]net/download | Status: online | Qakbot trojan being distributed via malicious email attachments',
            'url': 'https://urlhaus.abuse.ch/url/321654',
            'published': (base_time - timedelta(hours=11)).isoformat(),
            'severity': 'HIGH',
            'locations': ['Global'],
            'threat_type': 'Malicious URL',
            'malware': 'Qakbot'
        }
    ]
    
    return sample_threats

def main():
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║      GLOBAL THREAT INTELLIGENCE TRACKER v1.0 - DEMO MODE            ║
║                                                                       ║
║     Senior Security Engineering Tool for Worldwide Threat Analysis   ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """)
    
    print(f"{Fore.YELLOW}[i] Running in DEMO mode with sample threat data{Style.RESET_ALL}\n")
    
    # Generate sample threats
    print("[+] Loading sample threat intelligence data...")
    threats = generate_sample_threats()
    print(f"    ✓ Loaded {len(threats)} sample threats\n")
    
    # Analyze threats
    print("[+] Enriching threats with MITRE ATT&CK mappings...")
    analyzer = ThreatAnalyzer(threats)
    enriched_threats = analyzer.enrich_threats()
    
    # Save analysis
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = f'data/demo_threat_analysis_{timestamp}.json'
    analyzer.save_analysis(output_path)
    
    # Visualize results
    visualizer = ThreatVisualizer(analyzer)
    
    # Display all views
    visualizer.display_summary_report()
    visualizer.display_dashboard()
    visualizer.display_recent_critical(5)
    visualizer.display_actor_view()
    visualizer.display_vector_view()
    visualizer.display_location_view()
    
    # Final output
    print(f"\n{Fore.GREEN}{Style.BRIGHT}[✓] Demo complete!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[i] Sample data saved to: {output_path}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[i] Total threats analyzed: {len(enriched_threats)}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}To test with live data, run: python3 threat_tracker.py{Style.RESET_ALL}\n")

if __name__ == '__main__':
    main()
