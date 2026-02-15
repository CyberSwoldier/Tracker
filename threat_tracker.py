#!/usr/bin/env python3
"""
Global Threat Intelligence Tracker
Senior-level security engineering tool for tracking worldwide threats

Features:
- Collects from 6 open-source threat intelligence feeds
- MITRE ATT&CK framework mapping
- Threat actor identification and profiling
- Geographic threat distribution analysis
- Attack vector and technique analysis
- Real-time severity assessment
"""

import sys
import os
import json
import argparse
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collectors import collect_all_threats
from analyzer import ThreatAnalyzer
from visualizer import ThreatVisualizer
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_banner():
    """Print application banner"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║           GLOBAL THREAT INTELLIGENCE TRACKER v1.0                    ║
║                                                                       ║
║     Senior Security Engineering Tool for Worldwide Threat Analysis   ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """
    print(banner)

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Global Threat Intelligence Tracker with MITRE ATT&CK Mapping'
    )
    parser.add_argument(
        '--view',
        choices=['dashboard', 'actor', 'vector', 'location', 'critical', 'summary', 'all'],
        default='all',
        help='View to display (default: all)'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Save analysis to JSON file'
    )
    parser.add_argument(
        '--no-collect',
        action='store_true',
        help='Skip data collection and use existing data'
    )
    parser.add_argument(
        '--load',
        type=str,
        help='Load analysis from existing JSON file'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    try:
        # Load existing data or collect new
        if args.load:
            print(f"[+] Loading threat data from {args.load}...")
            with open(args.load, 'r') as f:
                data = json.load(f)
                threats = data.get('threats', [])
        elif not args.no_collect:
            # Collect threat data
            threats = collect_all_threats()
            
            if not threats:
                print(f"\n{Fore.RED}[!] No threats collected. Check your internet connection.{Style.RESET_ALL}")
                return
        else:
            print(f"{Fore.RED}[!] No data source specified.{Style.RESET_ALL}")
            return
        
        # Analyze threats
        analyzer = ThreatAnalyzer(threats)
        enriched_threats = analyzer.enrich_threats()
        
        # Save analysis if requested
        if args.output:
            output_path = args.output
        else:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f'data/threat_analysis_{timestamp}.json'
        
        analyzer.save_analysis(output_path)
        
        # Visualize results
        visualizer = ThreatVisualizer(analyzer)
        
        # Display requested views
        if args.view == 'all':
            visualizer.display_summary_report()
            visualizer.display_dashboard()
            visualizer.display_recent_critical(5)
            visualizer.display_actor_view()
            visualizer.display_vector_view()
            visualizer.display_location_view()
        elif args.view == 'dashboard':
            visualizer.display_dashboard()
        elif args.view == 'actor':
            visualizer.display_actor_view()
        elif args.view == 'vector':
            visualizer.display_vector_view()
        elif args.view == 'location':
            visualizer.display_location_view()
        elif args.view == 'critical':
            visualizer.display_recent_critical(10)
        elif args.view == 'summary':
            visualizer.display_summary_report()
        
        # Final output message
        print(f"\n{Fore.GREEN}{Style.BRIGHT}[✓] Analysis complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Data saved to: {output_path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Total threats analyzed: {len(enriched_threats)}{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Operation cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()