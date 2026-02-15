#!/usr/bin/env python3
"""
Streamlit Web Dashboard for Global Threat Intelligence Tracker
"""

import streamlit as st
import pandas as pd
import json
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our modules
try:
    from collectors import collect_all_threats
    from analyzer import ThreatAnalyzer
    from mitre_mapping import THREAT_ACTORS, MITRE_TACTICS
except ImportError:
    st.error("Required modules not found. Ensure all Python files are in the same directory.")
    st.stop()

# Page configuration
st.set_page_config(
    page_title="Global Threat Intelligence Tracker",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }
    .critical-alert {
        background-color: #ffe6e6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #ff4444;
        margin: 1rem 0;
    }
    .high-alert {
        background-color: #fff4e6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 5px solid #ff9944;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'threats_data' not in st.session_state:
    st.session_state.threats_data = None
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = None
if 'last_update' not in st.session_state:
    st.session_state.last_update = None

def load_demo_data():
    """Load demo data for testing"""
    from demo import generate_sample_threats
    threats = generate_sample_threats()
    analyzer = ThreatAnalyzer(threats)
    analyzer.enrich_threats()
    return analyzer

def collect_live_data():
    """Collect live threat data"""
    with st.spinner("🔍 Collecting threat intelligence from 6 sources..."):
        threats = collect_all_threats()
        if threats:
            analyzer = ThreatAnalyzer(threats)
            analyzer.enrich_threats()
            return analyzer
        else:
            st.error("Failed to collect threat data. Please check your internet connection.")
            return None

def severity_color(severity):
    """Get color for severity level"""
    colors = {
        'CRITICAL': '#ff4444',
        'HIGH': '#ff9944',
        'MEDIUM': '#ffdd44',
        'LOW': '#44ff44'
    }
    return colors.get(severity, '#888888')

def create_severity_chart(stats):
    """Create severity distribution chart"""
    severity_data = stats.get('by_severity', {})
    
    df = pd.DataFrame([
        {'Severity': k, 'Count': v} 
        for k, v in severity_data.items()
    ])
    
    color_map = {
        'CRITICAL': '#ff4444',
        'HIGH': '#ff9944',
        'MEDIUM': '#ffdd44',
        'LOW': '#44ff44'
    }
    
    fig = px.bar(df, x='Severity', y='Count', 
                 color='Severity',
                 color_discrete_map=color_map,
                 title='Threat Distribution by Severity')
    fig.update_layout(showlegend=False)
    return fig

def create_source_chart(stats):
    """Create source distribution chart"""
    source_data = stats.get('by_source', {})
    
    df = pd.DataFrame([
        {'Source': k, 'Count': v} 
        for k, v in source_data.items()
    ])
    
    fig = px.pie(df, values='Count', names='Source', 
                 title='Threats by Data Source')
    return fig

def create_location_map(stats):
    """Create geographic threat map"""
    location_data = stats.get('by_location', {})
    
    df = pd.DataFrame([
        {'Location': k, 'Threats': v} 
        for k, v in location_data.items()
        if k != 'Global'  # Exclude global for map
    ])
    
    if not df.empty:
        fig = px.bar(df.sort_values('Threats', ascending=True).tail(15), 
                     x='Threats', y='Location', 
                     orientation='h',
                     title='Top 15 Targeted Locations',
                     color='Threats',
                     color_continuous_scale='Reds')
        return fig
    return None

def create_technique_chart(stats):
    """Create MITRE technique chart"""
    technique_data = stats.get('mitre_techniques', {})
    
    if technique_data:
        df = pd.DataFrame([
            {'Technique': k, 'Count': v} 
            for k, v in technique_data.most_common(10)
        ])
        
        fig = px.bar(df, x='Count', y='Technique', 
                     orientation='h',
                     title='Top 10 MITRE ATT&CK Techniques',
                     color='Count',
                     color_continuous_scale='Blues')
        return fig
    return None

def create_tactic_chart(stats):
    """Create MITRE tactic chart"""
    tactic_data = stats.get('mitre_tactics', {})
    
    if tactic_data:
        df = pd.DataFrame([
            {'Tactic': k, 'Count': v} 
            for k, v in tactic_data.most_common()
        ])
        
        fig = px.bar(df, x='Tactic', y='Count', 
                     title='MITRE ATT&CK Tactics Distribution',
                     color='Count',
                     color_continuous_scale='Purples')
        fig.update_xaxis(tickangle=45)
        return fig
    return None

def create_actor_chart(stats):
    """Create threat actor chart"""
    actor_data = stats.get('threat_actors', {})
    
    if actor_data:
        df = pd.DataFrame([
            {'Actor': k, 'Threats': v} 
            for k, v in actor_data.items()
        ])
        
        fig = px.bar(df, x='Actor', y='Threats', 
                     title='Identified Threat Actors',
                     color='Threats',
                     color_continuous_scale='Reds')
        return fig
    return None

def display_threat_card(threat, index):
    """Display individual threat card"""
    severity = threat.get('severity', 'UNKNOWN')
    color = severity_color(severity)
    
    # Determine alert style
    if severity == 'CRITICAL':
        alert_class = "critical-alert"
    elif severity == 'HIGH':
        alert_class = "high-alert"
    else:
        alert_class = "metric-card"
    
    with st.container():
        st.markdown(f'<div class="{alert_class}">', unsafe_allow_html=True)
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.markdown(f"### {threat['title']}")
            st.markdown(f"**Source:** {threat['source']}")
            st.markdown(f"**Type:** {threat.get('threat_type', 'Unknown')}")
            
            # Show description
            if threat.get('description'):
                with st.expander("📄 Details"):
                    st.write(threat['description'][:500])
            
            # Show locations
            if threat.get('locations'):
                st.markdown(f"**📍 Locations:** {', '.join(threat['locations'][:5])}")
        
        with col2:
            st.markdown(f"<h2 style='color: {color}; text-align: center;'>{severity}</h2>", 
                       unsafe_allow_html=True)
            st.markdown(f"**Published:** {threat.get('published', 'Unknown')[:10]}")
        
        # MITRE Techniques
        if threat.get('mitre_techniques'):
            st.markdown("**🎯 MITRE Techniques:**")
            techniques = [f"`{t['technique_id']}`: {t['technique_name']}" 
                         for t in threat['mitre_techniques'][:3]]
            st.markdown(" • " + "\n • ".join(techniques))
        
        # Threat Actors
        if threat.get('potential_actors'):
            actors = [a['actor'] for a in threat['potential_actors']]
            st.markdown(f"**👥 Threat Actors:** {', '.join(actors)}")
        
        # URL
        if threat.get('url'):
            st.markdown(f"[🔗 View Source]({threat['url']})")
        
        st.markdown('</div>', unsafe_allow_html=True)

def main():
    """Main Streamlit app"""
    
    # Header
    st.markdown('<div class="main-header">🛡️ Global Threat Intelligence Tracker</div>', 
                unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/000000/security-checked.png", width=100)
        st.title("Control Panel")
        
        st.markdown("---")
        
        # Data source selection
        data_source = st.radio(
            "Data Source:",
            ["Demo Data", "Live Collection"],
            help="Demo data is faster, Live collection requires internet"
        )
        
        # Collect button
        if st.button("🔄 Refresh Data", type="primary", use_container_width=True):
            if data_source == "Demo Data":
                st.session_state.analyzer = load_demo_data()
                st.session_state.last_update = datetime.now()
                st.success("✅ Demo data loaded!")
                st.rerun()
            else:
                analyzer = collect_live_data()
                if analyzer:
                    st.session_state.analyzer = analyzer
                    st.session_state.last_update = datetime.now()
                    st.success("✅ Live data collected!")
                    st.rerun()
        
        st.markdown("---")
        
        # View selection
        view_mode = st.selectbox(
            "View:",
            ["📊 Dashboard", "⚠️ Critical Threats", "👥 Threat Actors", 
             "🎯 Attack Vectors", "🌍 Geographic", "📋 All Threats"]
        )
        
        st.markdown("---")
        
        # Filters
        st.subheader("Filters")
        
        severity_filter = st.multiselect(
            "Severity:",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=[]
        )
        
        if st.session_state.analyzer:
            stats = st.session_state.analyzer.get_statistics()
            
            # Source filter
            sources = list(stats.get('by_source', {}).keys())
            source_filter = st.multiselect(
                "Source:",
                sources,
                default=[]
            )
        
        st.markdown("---")
        
        # Info
        if st.session_state.last_update:
            st.info(f"Last Update: {st.session_state.last_update.strftime('%H:%M:%S')}")
        
        st.markdown("---")
        st.markdown("### About")
        st.markdown("""
        **Threat Tracker v1.0**
        
        Collects from 6 sources:
        - CISA Alerts
        - NVD CVE Feed
        - ThreatFox
        - AlienVault OTX
        - URLhaus
        - The Hacker News
        
        Features:
        - MITRE ATT&CK Mapping
        - Threat Actor ID
        - Geographic Analysis
        """)
    
    # Main content
    if st.session_state.analyzer is None:
        st.info("👈 Click **Refresh Data** in the sidebar to get started!")
        st.markdown("""
        ### Welcome to the Global Threat Intelligence Tracker
        
        This dashboard provides real-time threat intelligence from multiple open-source feeds,
        automatically mapped to the MITRE ATT&CK framework.
        
        **Features:**
        - 📊 Real-time threat collection from 6 sources
        - 🎯 MITRE ATT&CK technique mapping
        - 👥 Threat actor identification
        - 🌍 Geographic threat distribution
        - ⚠️ Severity-based prioritization
        
        **Get Started:**
        1. Select "Demo Data" or "Live Collection" in the sidebar
        2. Click "Refresh Data"
        3. Explore different views
        """)
        return
    
    analyzer = st.session_state.analyzer
    threats = analyzer.enriched_threats
    stats = analyzer.get_statistics()
    
    # Apply filters
    filtered_threats = threats.copy()
    
    if severity_filter:
        filtered_threats = [t for t in filtered_threats if t.get('severity') in severity_filter]
    
    if 'source_filter' in locals() and source_filter:
        filtered_threats = [t for t in filtered_threats if t.get('source') in source_filter]
    
    # Display based on view mode
    if view_mode == "📊 Dashboard":
        display_dashboard(stats, filtered_threats)
    
    elif view_mode == "⚠️ Critical Threats":
        display_critical_threats(filtered_threats)
    
    elif view_mode == "👥 Threat Actors":
        display_threat_actors(analyzer, filtered_threats)
    
    elif view_mode == "🎯 Attack Vectors":
        display_attack_vectors(analyzer, stats)
    
    elif view_mode == "🌍 Geographic":
        display_geographic(analyzer, stats)
    
    elif view_mode == "📋 All Threats":
        display_all_threats(filtered_threats)

def display_dashboard(stats, threats):
    """Display main dashboard"""
    st.header("📊 Threat Intelligence Dashboard")
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Threats", stats.get('total_threats', 0))
    
    with col2:
        critical_count = stats.get('by_severity', {}).get('CRITICAL', 0)
        st.metric("Critical", critical_count, 
                 delta=None if critical_count == 0 else "High Priority",
                 delta_color="inverse")
    
    with col3:
        high_count = stats.get('by_severity', {}).get('HIGH', 0)
        st.metric("High Severity", high_count)
    
    with col4:
        actor_count = len([a for a, c in stats.get('threat_actors', {}).items() if c > 0])
        st.metric("Active Actors", actor_count)
    
    st.markdown("---")
    
    # Charts row 1
    col1, col2 = st.columns(2)
    
    with col1:
        fig = create_severity_chart(stats)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = create_source_chart(stats)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
    
    # Charts row 2
    col1, col2 = st.columns(2)
    
    with col1:
        fig = create_technique_chart(stats)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = create_location_map(stats)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
    
    # Recent critical threats
    st.markdown("---")
    st.subheader("🔥 Recent Critical Threats")
    
    critical_threats = [t for t in threats if t.get('severity') == 'CRITICAL'][:5]
    
    if critical_threats:
        for i, threat in enumerate(critical_threats):
            display_threat_card(threat, i)
    else:
        st.success("No critical threats detected!")

def display_critical_threats(threats):
    """Display critical threats view"""
    st.header("⚠️ Critical & High Severity Threats")
    
    critical_high = [t for t in threats if t.get('severity') in ['CRITICAL', 'HIGH']]
    
    if not critical_high:
        st.success("✅ No critical or high severity threats detected!")
        return
    
    st.warning(f"Found {len(critical_high)} threats requiring attention")
    
    for i, threat in enumerate(critical_high):
        display_threat_card(threat, i)

def display_threat_actors(analyzer, threats):
    """Display threat actors view"""
    st.header("👥 Threat Actor Intelligence")
    
    actor_profiles = analyzer.generate_actor_profile()
    
    # Active actors
    active_actors = {k: v for k, v in actor_profiles.items() 
                    if v['recent_activity_count'] > 0}
    
    if active_actors:
        st.subheader("🚨 Active Threat Actors")
        
        for actor, profile in active_actors.items():
            with st.expander(f"🎯 {actor} - {profile['recent_activity_count']} threats detected"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Origin:** {profile['origin']}")
                    st.markdown(f"**Aliases:** {', '.join(profile['aliases'][:3])}")
                    st.markdown(f"**Targets:** {', '.join(profile['targets'])}")
                
                with col2:
                    st.markdown(f"**Known Techniques:**")
                    for tech in profile['known_techniques'][:5]:
                        st.markdown(f"- `{tech}`")
                
                if profile['recent_threats']:
                    st.markdown("**Recent Activity:**")
                    for threat in profile['recent_threats']:
                        st.markdown(f"- [{threat['severity']}] {threat['title'][:60]}...")
    
    # All actors
    st.markdown("---")
    st.subheader("📋 Known Threat Actors")
    
    for actor, profile in actor_profiles.items():
        with st.expander(f"{actor} ({profile['origin']})"):
            st.markdown(f"**Aliases:** {', '.join(profile['aliases'])}")
            st.markdown(f"**Primary Targets:** {', '.join(profile['targets'])}")
            st.markdown(f"**Known Techniques:** {', '.join(profile['known_techniques'])}")
            
            if profile['recent_activity_count'] > 0:
                st.info(f"⚠️ {profile['recent_activity_count']} recent threats detected")

def display_attack_vectors(analyzer, stats):
    """Display attack vectors view"""
    st.header("🎯 Attack Vector Analysis")
    
    vector_analysis = analyzer.generate_vector_analysis()
    
    # Tactics
    col1, col2 = st.columns(2)
    
    with col1:
        fig = create_tactic_chart(stats)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = create_technique_chart(stats)
        if fig:
            st.plotly_chart(fig, use_container_width=True)
    
    # Top techniques table
    st.markdown("---")
    st.subheader("Top MITRE ATT&CK Techniques")
    
    if vector_analysis['top_techniques']:
        df = pd.DataFrame(vector_analysis['top_techniques'])
        st.dataframe(df, use_container_width=True)

def display_geographic(analyzer, stats):
    """Display geographic view"""
    st.header("🌍 Geographic Threat Distribution")
    
    location_heatmap = analyzer.generate_location_heatmap()
    
    # Map
    fig = create_location_map(stats)
    if fig:
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # Location details
    st.subheader("Location Details")
    
    sorted_locations = sorted(
        location_heatmap.items(),
        key=lambda x: x[1]['threat_count'],
        reverse=True
    )
    
    for location, data in sorted_locations[:10]:
        with st.expander(f"📍 {location} - {data['threat_count']} threats"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Severity Breakdown:**")
                for sev, count in data['severity_breakdown'].items():
                    st.markdown(f"- {sev}: {count}")
            
            with col2:
                st.markdown("**Threat Types:**")
                for ttype, count in list(data['threat_types'].items())[:5]:
                    st.markdown(f"- {ttype}: {count}")
            
            if data['actors']:
                st.markdown(f"**Threat Actors:** {', '.join(data['actors'])}")

def display_all_threats(threats):
    """Display all threats view"""
    st.header("📋 All Threats")
    
    st.info(f"Showing {len(threats)} threats")
    
    # Search
    search_term = st.text_input("🔍 Search threats:", "")
    
    if search_term:
        threats = [t for t in threats 
                  if search_term.lower() in t.get('title', '').lower() 
                  or search_term.lower() in t.get('description', '').lower()]
        st.info(f"Found {len(threats)} matching threats")
    
    # Display
    for i, threat in enumerate(threats):
        display_threat_card(threat, i)

if __name__ == "__main__":
    main()