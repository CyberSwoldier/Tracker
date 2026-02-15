"""
Threat Analyzer - Process and enrich threat data with MITRE mappings
"""

import json
from datetime import datetime
from collections import defaultdict, Counter
from mitre_mapping import map_to_mitre, identify_threat_actor, THREAT_ACTORS

class ThreatAnalyzer:
    """Analyze and enrich threat intelligence data"""
    
    def __init__(self, threats):
        self.threats = threats
        self.enriched_threats = []
        
    def enrich_threats(self):
        """Enrich threats with MITRE ATT&CK mappings and actor identification"""
        print("\n[+] Enriching threats with MITRE ATT&CK mappings...")
        
        for threat in self.threats:
            # Combine title and description for analysis
            full_text = f"{threat.get('title', '')} {threat.get('description', '')}"
            
            # Map to MITRE techniques
            mitre_techniques = map_to_mitre(full_text)
            
            # Identify potential threat actors
            potential_actors = identify_threat_actor(full_text)
            
            # Create enriched threat
            enriched = {
                **threat,
                'mitre_techniques': mitre_techniques,
                'potential_actors': potential_actors,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            self.enriched_threats.append(enriched)
        
        print(f"    ✓ Enriched {len(self.enriched_threats)} threats")
        return self.enriched_threats
    
    def get_statistics(self):
        """Generate statistics from threat data"""
        stats = {
            'total_threats': len(self.enriched_threats),
            'by_source': Counter(),
            'by_severity': Counter(),
            'by_type': Counter(),
            'by_location': Counter(),
            'mitre_techniques': Counter(),
            'mitre_tactics': Counter(),
            'threat_actors': Counter(),
            'collection_time': datetime.now().isoformat()
        }
        
        for threat in self.enriched_threats:
            # Count by source
            stats['by_source'][threat.get('source', 'Unknown')] += 1
            
            # Count by severity
            stats['by_severity'][threat.get('severity', 'Unknown')] += 1
            
            # Count by type
            stats['by_type'][threat.get('threat_type', 'Unknown')] += 1
            
            # Count by location
            for location in threat.get('locations', ['Unknown']):
                stats['by_location'][location] += 1
            
            # Count MITRE techniques and tactics
            for technique in threat.get('mitre_techniques', []):
                stats['mitre_techniques'][f"{technique['technique_id']}: {technique['technique_name']}"] += 1
                stats['mitre_tactics'][technique['tactic_name']] += 1
            
            # Count threat actors
            for actor_data in threat.get('potential_actors', []):
                stats['threat_actors'][actor_data['actor']] += 1
        
        return stats
    
    def get_by_severity(self, severity):
        """Filter threats by severity level"""
        return [t for t in self.enriched_threats if t.get('severity') == severity]
    
    def get_by_location(self, location):
        """Filter threats by location"""
        return [t for t in self.enriched_threats 
                if location in t.get('locations', [])]
    
    def get_by_actor(self, actor_name):
        """Filter threats by threat actor"""
        matching = []
        for threat in self.enriched_threats:
            for actor_data in threat.get('potential_actors', []):
                if actor_data['actor'] == actor_name:
                    matching.append(threat)
                    break
        return matching
    
    def get_by_technique(self, technique_id):
        """Filter threats by MITRE technique"""
        matching = []
        for threat in self.enriched_threats:
            for technique in threat.get('mitre_techniques', []):
                if technique['technique_id'] == technique_id:
                    matching.append(threat)
                    break
        return matching
    
    def generate_actor_profile(self):
        """Generate threat actor profile view"""
        actor_profiles = {}
        
        for actor, actor_data in THREAT_ACTORS.items():
            # Find threats associated with this actor
            actor_threats = self.get_by_actor(actor)
            
            profile = {
                'name': actor,
                'aliases': actor_data['aliases'],
                'origin': actor_data['origin'],
                'known_techniques': actor_data['techniques'],
                'targets': actor_data['targets'],
                'recent_activity_count': len(actor_threats),
                'recent_threats': [
                    {
                        'title': t['title'],
                        'source': t['source'],
                        'severity': t['severity'],
                        'date': t['published']
                    }
                    for t in actor_threats[:5]  # Top 5 recent
                ]
            }
            
            actor_profiles[actor] = profile
        
        return actor_profiles
    
    def generate_vector_analysis(self):
        """Analyze attack vectors and techniques"""
        vector_analysis = {
            'top_techniques': [],
            'top_tactics': [],
            'attack_chains': [],
            'emerging_patterns': []
        }
        
        # Get top techniques
        technique_counts = Counter()
        tactic_counts = Counter()
        
        for threat in self.enriched_threats:
            for technique in threat.get('mitre_techniques', []):
                technique_counts[technique['technique_id']] += 1
                tactic_counts[technique['tactic_name']] += 1
        
        # Format top techniques
        for tech_id, count in technique_counts.most_common(10):
            # Find technique name
            tech_name = "Unknown"
            for threat in self.enriched_threats:
                for technique in threat.get('mitre_techniques', []):
                    if technique['technique_id'] == tech_id:
                        tech_name = technique['technique_name']
                        break
                if tech_name != "Unknown":
                    break
            
            vector_analysis['top_techniques'].append({
                'technique_id': tech_id,
                'technique_name': tech_name,
                'count': count
            })
        
        # Format top tactics
        for tactic, count in tactic_counts.most_common(10):
            vector_analysis['top_tactics'].append({
                'tactic': tactic,
                'count': count
            })
        
        return vector_analysis
    
    def generate_location_heatmap(self):
        """Generate location-based threat analysis"""
        location_data = defaultdict(lambda: {
            'threat_count': 0,
            'severity_breakdown': Counter(),
            'threat_types': Counter(),
            'actors': set(),
            'techniques': Counter()
        })
        
        for threat in self.enriched_threats:
            for location in threat.get('locations', ['Unknown']):
                loc_data = location_data[location]
                loc_data['threat_count'] += 1
                loc_data['severity_breakdown'][threat.get('severity', 'Unknown')] += 1
                loc_data['threat_types'][threat.get('threat_type', 'Unknown')] += 1
                
                # Add actors
                for actor_data in threat.get('potential_actors', []):
                    loc_data['actors'].add(actor_data['actor'])
                
                # Add techniques
                for technique in threat.get('mitre_techniques', []):
                    loc_data['techniques'][technique['technique_id']] += 1
        
        # Convert to serializable format
        location_heatmap = {}
        for location, data in location_data.items():
            location_heatmap[location] = {
                'threat_count': data['threat_count'],
                'severity_breakdown': dict(data['severity_breakdown']),
                'threat_types': dict(data['threat_types']),
                'actors': list(data['actors']),
                'top_techniques': [
                    {'id': tech, 'count': count}
                    for tech, count in data['techniques'].most_common(5)
                ]
            }
        
        return location_heatmap
    
    def save_analysis(self, filepath):
        """Save enriched threats and analysis to JSON"""
        analysis_data = {
            'threats': self.enriched_threats,
            'statistics': self.get_statistics(),
            'actor_profiles': self.generate_actor_profile(),
            'vector_analysis': self.generate_vector_analysis(),
            'location_heatmap': self.generate_location_heatmap()
        }
        
        with open(filepath, 'w') as f:
            json.dump(analysis_data, f, indent=2, default=str)
        
        print(f"\n[+] Analysis saved to {filepath}")
