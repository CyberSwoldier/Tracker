"""
MITRE ATT&CK Framework Mapping Module
Maps threat indicators to MITRE ATT&CK techniques and tactics
"""

MITRE_TACTICS = {
    'TA0001': 'Initial Access',
    'TA0002': 'Execution',
    'TA0003': 'Persistence',
    'TA0004': 'Privilege Escalation',
    'TA0005': 'Defense Evasion',
    'TA0006': 'Credential Access',
    'TA0007': 'Discovery',
    'TA0008': 'Lateral Movement',
    'TA0009': 'Collection',
    'TA0010': 'Exfiltration',
    'TA0011': 'Command and Control',
    'TA0040': 'Impact',
    'TA0042': 'Resource Development',
    'TA0043': 'Reconnaissance'
}

# Common techniques mapped to keywords for automatic detection
TECHNIQUE_KEYWORDS = {
    'T1566': {
        'name': 'Phishing',
        'tactic': 'TA0001',
        'keywords': ['phishing', 'spearphishing', 'email attack', 'malicious email', 'credential harvesting']
    },
    'T1190': {
        'name': 'Exploit Public-Facing Application',
        'tactic': 'TA0001',
        'keywords': ['exploit', 'vulnerability', 'CVE', 'zero-day', 'RCE', 'remote code execution']
    },
    'T1059': {
        'name': 'Command and Scripting Interpreter',
        'tactic': 'TA0002',
        'keywords': ['powershell', 'bash', 'command line', 'script', 'macro']
    },
    'T1486': {
        'name': 'Data Encrypted for Impact',
        'tactic': 'TA0040',
        'keywords': ['ransomware', 'encryption', 'locked files', 'ransom']
    },
    'T1071': {
        'name': 'Application Layer Protocol',
        'tactic': 'TA0011',
        'keywords': ['C2', 'command and control', 'C&C', 'backdoor', 'botnet']
    },
    'T1003': {
        'name': 'OS Credential Dumping',
        'tactic': 'TA0006',
        'keywords': ['credential dump', 'mimikatz', 'password steal', 'hash dump']
    },
    'T1078': {
        'name': 'Valid Accounts',
        'tactic': 'TA0001',
        'keywords': ['compromised account', 'stolen credentials', 'account takeover', 'brute force']
    },
    'T1027': {
        'name': 'Obfuscated Files or Information',
        'tactic': 'TA0005',
        'keywords': ['obfuscation', 'encoded', 'packed', 'steganography']
    },
    'T1105': {
        'name': 'Ingress Tool Transfer',
        'tactic': 'TA0011',
        'keywords': ['download', 'malware delivery', 'payload', 'dropper']
    },
    'T1518': {
        'name': 'Software Discovery',
        'tactic': 'TA0007',
        'keywords': ['reconnaissance', 'scanning', 'enumeration', 'discovery']
    },
    'T1110': {
        'name': 'Brute Force',
        'tactic': 'TA0006',
        'keywords': ['brute force', 'password spray', 'credential stuffing', 'dictionary attack']
    },
    'T1133': {
        'name': 'External Remote Services',
        'tactic': 'TA0001',
        'keywords': ['VPN', 'RDP', 'remote access', 'remote desktop']
    },
    'T1053': {
        'name': 'Scheduled Task/Job',
        'tactic': 'TA0003',
        'keywords': ['scheduled task', 'cron', 'persistence mechanism']
    },
    'T1021': {
        'name': 'Remote Services',
        'tactic': 'TA0008',
        'keywords': ['lateral movement', 'SMB', 'SSH', 'WMI']
    },
    'T1567': {
        'name': 'Exfiltration Over Web Service',
        'tactic': 'TA0010',
        'keywords': ['data exfiltration', 'data theft', 'stolen data']
    }
}

# Threat actor groups with known TTPs
THREAT_ACTORS = {
    'APT28': {
        'aliases': ['Fancy Bear', 'Sofacy', 'Sednit', 'STRONTIUM'],
        'origin': 'Russia',
        'techniques': ['T1566', 'T1190', 'T1059', 'T1071'],
        'targets': ['Government', 'Military', 'Media']
    },
    'APT29': {
        'aliases': ['Cozy Bear', 'The Dukes', 'NOBELIUM'],
        'origin': 'Russia',
        'techniques': ['T1566', 'T1078', 'T1071', 'T1027'],
        'targets': ['Government', 'Think Tanks', 'Healthcare']
    },
    'APT41': {
        'aliases': ['Winnti', 'Barium', 'Double Dragon'],
        'origin': 'China',
        'techniques': ['T1190', 'T1059', 'T1105', 'T1003'],
        'targets': ['Technology', 'Healthcare', 'Gaming', 'Telecommunications']
    },
    'Lazarus': {
        'aliases': ['Hidden Cobra', 'Zinc', 'Labyrinth Chollima'],
        'origin': 'North Korea',
        'techniques': ['T1566', 'T1486', 'T1071', 'T1567'],
        'targets': ['Financial', 'Cryptocurrency', 'Defense']
    },
    'FIN7': {
        'aliases': ['Carbanak'],
        'origin': 'Russia',
        'techniques': ['T1566', 'T1059', 'T1003', 'T1105'],
        'targets': ['Retail', 'Hospitality', 'Financial']
    },
    'Sandworm': {
        'aliases': ['Voodoo Bear', 'ELECTRUM'],
        'origin': 'Russia',
        'techniques': ['T1190', 'T1486', 'T1059', 'T1021'],
        'targets': ['Critical Infrastructure', 'Energy', 'Government']
    }
}

def map_to_mitre(threat_description):
    """
    Automatically map threat description to MITRE ATT&CK techniques
    
    Args:
        threat_description (str): Description of the threat
        
    Returns:
        list: List of matched MITRE techniques with details
    """
    threat_lower = threat_description.lower()
    matched_techniques = []
    
    for tech_id, tech_data in TECHNIQUE_KEYWORDS.items():
        for keyword in tech_data['keywords']:
            if keyword in threat_lower:
                matched_techniques.append({
                    'technique_id': tech_id,
                    'technique_name': tech_data['name'],
                    'tactic_id': tech_data['tactic'],
                    'tactic_name': MITRE_TACTICS.get(tech_data['tactic'], 'Unknown'),
                    'matched_keyword': keyword
                })
                break  # Only match once per technique
    
    return matched_techniques

def identify_threat_actor(threat_description):
    """
    Identify potential threat actor based on TTPs and keywords
    
    Args:
        threat_description (str): Description of the threat
        
    Returns:
        list: List of potential threat actors
    """
    threat_lower = threat_description.lower()
    potential_actors = []
    
    for actor, actor_data in THREAT_ACTORS.items():
        # Check for direct name mentions
        if actor.lower() in threat_lower:
            potential_actors.append({
                'actor': actor,
                'confidence': 'HIGH',
                'reason': 'Direct mention',
                'data': actor_data
            })
            continue
            
        # Check for alias mentions
        for alias in actor_data['aliases']:
            if alias.lower() in threat_lower:
                potential_actors.append({
                    'actor': actor,
                    'confidence': 'HIGH',
                    'reason': f'Alias match: {alias}',
                    'data': actor_data
                })
                break
    
    return potential_actors

def get_technique_details(technique_id):
    """Get details for a specific MITRE technique"""
    return TECHNIQUE_KEYWORDS.get(technique_id, {})

def get_tactic_name(tactic_id):
    """Get tactic name from tactic ID"""
    return MITRE_TACTICS.get(tactic_id, 'Unknown')