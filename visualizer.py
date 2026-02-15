"""
Threat Visualizer - Display threat data in various views
"""

from datetime import datetime
from collections import Counter
from colorama import Fore, Back, Style, init
from tabulate import tabulate

# Initialize colorama
init(autoreset=True)

class ThreatVisualizer:
    """Visualize threat intelligence data in terminal"""
    
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.threats = analyzer.enriched_threats
        
    def _get_severity_color(self, severity):
        """Get color for severity level"""
        colors = {
            'CRITICAL': Fore.RED + Back.WHITE,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN
        }
        return colors.get(severity, Fore.WHITE)
    
    def print_header(self, title):
        """Print formatted header"""
        width = 80
        print("\n" + "=" * width)
        print(f"{Fore.CYAN}{Style.BRIGHT}{title.center(width)}{Style.RESET_ALL}")
        print("=" * width + "\n")
    
    def display_dashboard(self):
        """Display main threat dashboard"""
        self.print_header("GLOBAL THREAT INTELLIGENCE DASHBOARD")
        
        stats = self.analyzer.get_statistics()
        
        print(f"{Fore.CYAN}Collection Time:{Style.RESET_ALL} {stats['collection_time']}")
        print(f"{Fore.CYAN}Total Threats:{Style.RESET_ALL} {stats['total_threats']}\n")
        
        # Severity breakdown
        print(f"{Fore.YELLOW}{Style.BRIGHT}═══ SEVERITY BREAKDOWN ═══{Style.RESET_ALL}")
        severity_data = []
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = stats['by_severity'].get(severity, 0)
            if count > 0:
                color = self._get_severity_color(severity)
                bar = "█" * min(count, 50)
                severity_data.append([
                    f"{color}{severity}{Style.RESET_ALL}",
                    count,
                    f"{color}{bar}{Style.RESET_ALL}"
                ])
        
        print(tabulate(severity_data, headers=['Severity', 'Count', 'Distribution'], tablefmt='simple'))
        
        # Source breakdown
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}═══ THREATS BY SOURCE ═══{Style.RESET_ALL}")
        source_data = [
            [source, count]
            for source, count in stats['by_source'].most_common()
        ]
        print(tabulate(source_data, headers=['Source', 'Count'], tablefmt='simple'))
        
        # Top locations
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}═══ TOP TARGETED LOCATIONS ═══{Style.RESET_ALL}")
        location_data = [
            [location, count]
            for location, count in stats['by_location'].most_common(10)
        ]
        print(tabulate(location_data, headers=['Location', 'Threats'], tablefmt='simple'))
    
    def display_actor_view(self):
        """Display threat actor view"""
        self.print_header("THREAT ACTOR INTELLIGENCE")
        
        actor_profiles = self.analyzer.generate_actor_profile()
        
        for actor, profile in actor_profiles.items():
            if profile['recent_activity_count'] > 0:
                print(f"\n{Fore.RED}{Style.BRIGHT}┌─ {actor} ─────────────────────────────────────────┐{Style.RESET_ALL}")
                print(f"   {Fore.CYAN}Origin:{Style.RESET_ALL} {profile['origin']}")
                print(f"   {Fore.CYAN}Aliases:{Style.RESET_ALL} {', '.join(profile['aliases'][:3])}")
                print(f"   {Fore.CYAN}Targets:{Style.RESET_ALL} {', '.join(profile['targets'])}")
                print(f"   {Fore.CYAN}Recent Activity:{Style.RESET_ALL} {profile['recent_activity_count']} threats detected")
                
                if profile['recent_threats']:
                    print(f"\n   {Fore.YELLOW}Recent Threats:{Style.RESET_ALL}")
                    for threat in profile['recent_threats'][:3]:
                        severity_color = self._get_severity_color(threat['severity'])
                        print(f"   • [{severity_color}{threat['severity']}{Style.RESET_ALL}] {threat['title'][:60]}")
                        print(f"     Source: {threat['source']}")
                
                print(f"{Fore.RED}└{'─' * 50}┘{Style.RESET_ALL}")
    
    def display_vector_view(self):
        """Display attack vector and technique analysis"""
        self.print_header("ATTACK VECTOR & TECHNIQUE ANALYSIS")
        
        vector_analysis = self.analyzer.generate_vector_analysis()
        
        # Top techniques
        print(f"{Fore.YELLOW}{Style.BRIGHT}═══ TOP MITRE ATT&CK TECHNIQUES ═══{Style.RESET_ALL}\n")
        
        technique_data = []
        for technique in vector_analysis['top_techniques']:
            technique_data.append([
                technique['technique_id'],
                technique['technique_name'],
                technique['count']
            ])
        
        print(tabulate(technique_data, headers=['ID', 'Technique', 'Occurrences'], tablefmt='grid'))
        
        # Top tactics
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}═══ TOP MITRE ATT&CK TACTICS ═══{Style.RESET_ALL}\n")
        
        tactic_data = []
        for tactic in vector_analysis['top_tactics']:
            tactic_data.append([
                tactic['tactic'],
                tactic['count'],
                "█" * min(tactic['count'], 30)
            ])
        
        print(tabulate(tactic_data, headers=['Tactic', 'Count', 'Frequency'], tablefmt='simple'))
    
    def display_location_view(self):
        """Display location-based threat heatmap"""
        self.print_header("GEOGRAPHIC THREAT DISTRIBUTION")
        
        location_heatmap = self.analyzer.generate_location_heatmap()
        
        # Sort by threat count
        sorted_locations = sorted(
            location_heatmap.items(),
            key=lambda x: x[1]['threat_count'],
            reverse=True
        )
        
        for location, data in sorted_locations[:15]:  # Top 15 locations
            print(f"\n{Fore.CYAN}{Style.BRIGHT}┌─ {location} ─────────────────────────────────────────┐{Style.RESET_ALL}")
            print(f"   {Fore.YELLOW}Total Threats:{Style.RESET_ALL} {data['threat_count']}")
            
            # Severity breakdown
            severity_str = " | ".join([
                f"{self._get_severity_color(sev)}{sev}: {count}{Style.RESET_ALL}"
                for sev, count in data['severity_breakdown'].items()
            ])
            print(f"   {Fore.YELLOW}Severity:{Style.RESET_ALL} {severity_str}")
            
            # Threat types
            if data['threat_types']:
                types_str = ", ".join([
                    f"{t_type}({count})"
                    for t_type, count in list(data['threat_types'].items())[:3]
                ])
                print(f"   {Fore.YELLOW}Types:{Style.RESET_ALL} {types_str}")
            
            # Associated actors
            if data['actors']:
                print(f"   {Fore.YELLOW}Threat Actors:{Style.RESET_ALL} {', '.join(data['actors'])}")
            
            # Top techniques
            if data['top_techniques']:
                tech_str = ", ".join([
                    f"{tech['id']}({tech['count']})"
                    for tech in data['top_techniques'][:3]
                ])
                print(f"   {Fore.YELLOW}Top Techniques:{Style.RESET_ALL} {tech_str}")
            
            print(f"{Fore.CYAN}└{'─' * 50}┘{Style.RESET_ALL}")
    
    def display_recent_critical(self, limit=10):
        """Display recent critical threats"""
        self.print_header("RECENT CRITICAL THREATS")
        
        critical_threats = [
            t for t in self.threats
            if t.get('severity') == 'CRITICAL'
        ][:limit]
        
        if not critical_threats:
            print(f"{Fore.GREEN}No critical threats detected in current collection.{Style.RESET_ALL}")
            return
        
        for i, threat in enumerate(critical_threats, 1):
            print(f"\n{Fore.RED}{Style.BRIGHT}[{i}] {threat['title']}{Style.RESET_ALL}")
            print(f"    {Fore.YELLOW}Source:{Style.RESET_ALL} {threat['source']}")
            print(f"    {Fore.YELLOW}Severity:{Style.RESET_ALL} {self._get_severity_color('CRITICAL')}CRITICAL{Style.RESET_ALL}")
            print(f"    {Fore.YELLOW}Locations:{Style.RESET_ALL} {', '.join(threat.get('locations', ['Unknown']))}")
            
            # Show MITRE techniques
            if threat.get('mitre_techniques'):
                techniques = ", ".join([
                    f"{t['technique_id']}"
                    for t in threat['mitre_techniques'][:3]
                ])
                print(f"    {Fore.YELLOW}MITRE Techniques:{Style.RESET_ALL} {techniques}")
            
            # Show actors if identified
            if threat.get('potential_actors'):
                actors = ", ".join([
                    a['actor'] for a in threat['potential_actors']
                ])
                print(f"    {Fore.YELLOW}Potential Actors:{Style.RESET_ALL} {actors}")
            
            print(f"    {Fore.YELLOW}URL:{Style.RESET_ALL} {threat.get('url', 'N/A')}")
    
    def display_summary_report(self):
        """Display executive summary report"""
        self.print_header("EXECUTIVE THREAT SUMMARY")
        
        stats = self.analyzer.get_statistics()
        
        print(f"{Fore.CYAN}{Style.BRIGHT}Report Generated:{Style.RESET_ALL} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{Style.BRIGHT}Analysis Period:{Style.RESET_ALL} Last 24 hours\n")
        
        # Key metrics
        critical_count = stats['by_severity'].get('CRITICAL', 0)
        high_count = stats['by_severity'].get('HIGH', 0)
        
        print(f"{Fore.YELLOW}{Style.BRIGHT}KEY METRICS:{Style.RESET_ALL}")
        print(f"  • Total Threats Detected: {stats['total_threats']}")
        print(f"  • {self._get_severity_color('CRITICAL')}Critical Threats: {critical_count}{Style.RESET_ALL}")
        print(f"  • {self._get_severity_color('HIGH')}High Severity Threats: {high_count}{Style.RESET_ALL}")
        print(f"  • Unique Threat Actors Identified: {len([a for a, c in stats['threat_actors'].items() if c > 0])}")
        print(f"  • Countries/Regions Affected: {len(stats['by_location'])}")
        
        # Top threats
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}TOP THREAT CATEGORIES:{Style.RESET_ALL}")
        for threat_type, count in stats['by_type'].most_common(5):
            print(f"  • {threat_type}: {count}")
        
        # Top threat actors
        if stats['threat_actors']:
            print(f"\n{Fore.YELLOW}{Style.BRIGHT}ACTIVE THREAT ACTORS:{Style.RESET_ALL}")
            for actor, count in stats['threat_actors'].most_common(5):
                print(f"  • {actor}: {count} associated threats")
        
        # Top techniques
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}MOST COMMON ATTACK TECHNIQUES:{Style.RESET_ALL}")
        for technique, count in stats['mitre_techniques'].most_common(5):
            print(f"  • {technique}: {count} occurrences")
        
        # Recommendations
        print(f"\n{Fore.RED}{Style.BRIGHT}RECOMMENDATIONS:{Style.RESET_ALL}")
        if critical_count > 0:
            print(f"  ⚠ {critical_count} critical threats require immediate attention")
        if 'Phishing' in str(stats['mitre_techniques']):
            print("  → Increase email security awareness training")
        if 'Ransomware' in str(stats):
            print("  → Verify backup integrity and offline backup availability")
        print("  → Review and update security controls based on detected TTPs")
        print("  → Monitor indicated threat actors and their known targeting patterns")