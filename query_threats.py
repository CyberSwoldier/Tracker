#!/usr/bin/env python3
"""
Threat Query Tool - Search and filter threat intelligence data
"""

import json
import sys
import argparse
from datetime import datetime
from colorama import Fore, Style, init
from tabulate import tabulate

init(autoreset=True)

def load_threat_data(filepath):
    """Load threat data from JSON file"""
    with open(filepath, 'r') as f:
        return json.load(f)

def search_threats(data, query):
    """Search threats by keyword"""
    query_lower = query.lower()
    results = []
    
    for threat in data['threats']:
        title = threat.get('title', '').lower()
        description = threat.get('description', '').lower()
        
        if query_lower in title or query_lower in description:
            results.append(threat)
    
    return results

def filter_by_severity(data, severity):
    """Filter threats by severity level"""
    return [t for t in data['threats'] if t.get('severity') == severity.upper()]

def filter_by_source(data, source):
    """Filter threats by data source"""
    return [t for t in data['threats'] if source.lower() in t.get('source', '').lower()]

def filter_by_location(data, location):
    """Filter threats by location"""
    return [t for t in data['threats'] if location in t.get('locations', [])]

def filter_by_actor(data, actor):
    """Filter threats by threat actor"""
    results = []
    for threat in data['threats']:
        for actor_data in threat.get('potential_actors', []):
            if actor.lower() in actor_data['actor'].lower():
                results.append(threat)
                break
    return results

def filter_by_technique(data, technique_id):
    """Filter threats by MITRE technique"""
    results = []
    for threat in data['threats']:
        for technique in threat.get('mitre_techniques', []):
            if technique_id.upper() in technique['technique_id']:
                results.append(threat)
                break
    return results

def display_threats(threats, limit=None):
    """Display threat results"""
    if not threats:
        print(f"{Fore.YELLOW}No threats found matching criteria.{Style.RESET_ALL}")
        return
    
    display_list = threats[:limit] if limit else threats
    
    print(f"\n{Fore.CYAN}Found {len(threats)} matching threats{Style.RESET_ALL}")
    if limit and len(threats) > limit:
        print(f"{Fore.YELLOW}Displaying first {limit} results{Style.RESET_ALL}\n")
    
    for i, threat in enumerate(display_list, 1):
        severity_colors = {
            'CRITICAL': Fore.RED + Back.WHITE,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.GREEN
        }
        sev_color = severity_colors.get(threat.get('severity', 'LOW'), Fore.WHITE)
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}[{i}] {threat['title']}{Style.RESET_ALL}")
        print(f"    Source: {threat['source']}")
        print(f"    Severity: {sev_color}{threat.get('severity', 'Unknown')}{Style.RESET_ALL}")
        print(f"    Type: {threat.get('threat_type', 'Unknown')}")
        print(f"    Locations: {', '.join(threat.get('locations', ['Unknown']))}")
        
        # MITRE techniques
        if threat.get('mitre_techniques'):
            techniques = ', '.join([
                f"{t['technique_id']}: {t['technique_name']}"
                for t in threat['mitre_techniques'][:2]
            ])
            print(f"    MITRE: {techniques}")
        
        # Threat actors
        if threat.get('potential_actors'):
            actors = ', '.join([a['actor'] for a in threat['potential_actors']])
            print(f"    Actors: {actors}")
        
        print(f"    URL: {threat.get('url', 'N/A')}")

def display_statistics(data):
    """Display data statistics"""
    stats = data.get('statistics', {})
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}THREAT INTELLIGENCE STATISTICS{Style.RESET_ALL}\n")
    print(f"Total Threats: {stats.get('total_threats', 0)}")
    print(f"Collection Time: {stats.get('collection_time', 'Unknown')}\n")
    
    # Severity
    print(f"{Fore.YELLOW}By Severity:{Style.RESET_ALL}")
    for severity, count in stats.get('by_severity', {}).items():
        print(f"  {severity}: {count}")
    
    # Sources
    print(f"\n{Fore.YELLOW}By Source:{Style.RESET_ALL}")
    for source, count in stats.get('by_source', {}).items():
        print(f"  {source}: {count}")
    
    # Locations
    print(f"\n{Fore.YELLOW}Top Locations:{Style.RESET_ALL}")
    sorted_locs = sorted(
        stats.get('by_location', {}).items(),
        key=lambda x: x[1],
        reverse=True
    )
    for location, count in sorted_locs[:10]:
        print(f"  {location}: {count}")

def main():
    parser = argparse.ArgumentParser(description='Query threat intelligence data')
    parser.add_argument('datafile', help='Path to threat analysis JSON file')
    parser.add_argument('--search', '-s', help='Search by keyword')
    parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], 
                       help='Filter by severity')
    parser.add_argument('--source', help='Filter by source')
    parser.add_argument('--location', help='Filter by location')
    parser.add_argument('--actor', help='Filter by threat actor')
    parser.add_argument('--technique', help='Filter by MITRE technique ID')
    parser.add_argument('--limit', type=int, default=20, help='Limit results (default: 20)')
    parser.add_argument('--stats', action='store_true', help='Show statistics only')
    
    args = parser.parse_args()
    
    try:
        # Load data
        data = load_threat_data(args.datafile)
        
        if args.stats:
            display_statistics(data)
            return
        
        # Apply filters
        results = data['threats']
        
        if args.search:
            results = [t for t in results 
                      if args.search.lower() in t.get('title', '').lower() 
                      or args.search.lower() in t.get('description', '').lower()]
        
        if args.severity:
            results = [t for t in results if t.get('severity') == args.severity]
        
        if args.source:
            results = [t for t in results 
                      if args.source.lower() in t.get('source', '').lower()]
        
        if args.location:
            results = [t for t in results if args.location in t.get('locations', [])]
        
        if args.actor:
            actor_results = []
            for t in results:
                for actor_data in t.get('potential_actors', []):
                    if args.actor.lower() in actor_data['actor'].lower():
                        actor_results.append(t)
                        break
            results = actor_results
        
        if args.technique:
            technique_results = []
            for t in results:
                for technique in t.get('mitre_techniques', []):
                    if args.technique.upper() in technique['technique_id']:
                        technique_results.append(t)
                        break
            results = technique_results
        
        # Display results
        display_threats(results, args.limit)
        
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File not found: {args.datafile}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()