# Global Threat Intelligence Tracker

A professional-grade threat intelligence tracking system with **Streamlit Web Dashboard** and command-line tools. Aggregates data from 6 open-source security feeds, maps threats to MITRE ATT&CK framework, and provides comprehensive analysis.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.31-red.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🚀 Quick Start - Web Dashboard

### Option 1: Deploy to Streamlit Cloud (Recommended)
1. Upload this repository to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your repo and deploy `streamlit_app.py`
4. **Done!** Your dashboard is live in 2 minutes

### Option 2: Run Locally
```bash
pip install -r requirements_streamlit.txt
streamlit run streamlit_app.py
```

Visit: `http://localhost:8501`

📖 **[Full Deployment Guide](STREAMLIT_DEPLOY.md)**

---

## 🎯 Features

### 🌐 Web Dashboard (Streamlit)
- **Interactive Charts** - Plotly visualizations
- **Real-time Data** - Live threat collection
- **Demo Mode** - Works immediately without setup
- **Multiple Views** - Dashboard, Actors, Vectors, Geographic
- **Search & Filter** - Find specific threats
- **Mobile Responsive** - Works on all devices
- **Professional UI** - Clean, modern design

### 💻 Command-Line Tools
- **threat_tracker.py** - Full CLI with multiple views
- **query_threats.py** - Advanced search and filtering
- **demo.py** - Demonstration with sample data

### 📊 Data Sources (6 Feeds)
1. **CISA Alerts** - US Cybersecurity alerts
2. **NVD CVE Feed** - Vulnerability database
3. **ThreatFox** - IOC database by abuse.ch
4. **AlienVault OTX** - Open Threat Exchange
5. **URLhaus** - Malicious URL database
6. **The Hacker News** - Security news feed

### 🎯 MITRE ATT&CK Integration
- **15+ Techniques** mapped automatically
- **14 Tactics** covering full kill chain
- **6 APT Groups** tracked (APT28, APT29, APT41, Lazarus, FIN7, Sandworm)
- **Automatic TTP** detection from threat descriptions

---

## 📁 What's Included

```
threat_tracker/
├── streamlit_app.py              🌐 Web Dashboard (NEW!)
├── collectors.py                 📡 Data collectors
├── analyzer.py                   🔍 Analysis engine
├── mitre_mapping.py              🎯 MITRE framework
├── demo.py                       🎪 Demo data
├── threat_tracker.py             💻 CLI tool
├── query_threats.py              🔎 Query tool
├── visualizer.py                 📊 Terminal viz
├── requirements_streamlit.txt    📦 Web dependencies
├── requirements.txt              📦 CLI dependencies
├── STREAMLIT_DEPLOY.md          📖 Deployment guide
├── README.md                     📖 This file
├── QUICKSTART.md                📖 Quick reference
└── OVERVIEW.md                  📖 Architecture
```

---

## 🎨 Dashboard Screenshots

### Main Dashboard
- Severity distribution charts
- Source breakdown pie chart
- Top MITRE techniques
- Geographic threat map
- Recent critical threats with details

### Available Views
1. **📊 Dashboard** - Overview with metrics and charts
2. **⚠️ Critical Threats** - High-priority alerts
3. **👥 Threat Actors** - APT group profiles  
4. **🎯 Attack Vectors** - MITRE technique analysis
5. **🌍 Geographic** - Location-based distribution
6. **📋 All Threats** - Complete searchable list

---

## 🚀 Installation & Usage

### Web Dashboard
```bash
# Install Streamlit dependencies
pip install -r requirements_streamlit.txt

# Run the dashboard
streamlit run streamlit_app.py
```

### Command Line Tools
```bash
# Install CLI dependencies
pip install -r requirements.txt

# Run full analysis
python3 threat_tracker.py

# Run demo
python3 demo.py

# Query threats
python3 query_threats.py data/*.json --severity CRITICAL
```

---

## 📊 Dashboard Features

### Interactive Controls
- **Data Source Toggle** - Demo vs Live collection
- **Refresh Button** - Update threat data
- **View Selector** - Switch between different analyses
- **Filters** - Severity and source filtering
- **Search** - Find specific threats

### Visualizations
- **Bar Charts** - Severity, sources, techniques
- **Pie Charts** - Source distribution
- **Geographic Maps** - Location-based threats
- **Metric Cards** - Key statistics
- **Color Coding** - Severity-based alerts

### Real-time Updates
- Click "Refresh Data" to update
- Demo mode works instantly
- Live mode collects from all 6 sources
- Results cached in session

---

## 🎯 Use Cases

### Security Operations Center (SOC)
- Daily threat briefings via dashboard
- Monitor critical threats in real-time
- Track threat actor activity
- Geographic threat monitoring

### Incident Response
- Quick threat actor lookup
- MITRE technique correlation
- IOC tracking and validation
- Campaign identification

### Threat Intelligence
- Multi-source aggregation
- Automated MITRE mapping
- Actor profiling
- Trend analysis

### Executive Reporting
- Clean visualizations
- Summary metrics
- Severity prioritization
- Exportable data

---

## 🔧 Configuration

### Streamlit Theme
Edit `.streamlit/config.toml`:
```toml
[theme]
primaryColor = "#1f77b4"
backgroundColor = "#ffffff"
```

### Add More Sources
Edit `collectors.py`:
```python
class YourSourceCollector(ThreatDataCollector):
    def collect(self):
        # Your collection logic
        return threats
```

### Customize MITRE
Edit `mitre_mapping.py`:
```python
TECHNIQUE_KEYWORDS = {
    'T1234': {
        'name': 'Your Technique',
        'keywords': ['keyword1', 'keyword2']
    }
}
```

---

## 🌐 Deployment Options

### 1. Streamlit Cloud (Easiest)
- Free hosting
- Auto-deploys from GitHub
- HTTPS included
- No server maintenance

### 2. Docker (Coming Soon)
```bash
docker build -t threat-tracker .
docker run -p 8501:8501 threat-tracker
```

### 3. Cloud Platforms
- **AWS**: EC2 or ECS
- **Google Cloud**: Cloud Run
- **Azure**: App Service
- **Heroku**: Free tier available

---

## 🔒 Security Considerations

### Data Privacy
- No authentication required
- Only public threat intelligence
- No sensitive data stored
- In-memory processing only

### Network Security
- HTTPS-only connections
- Standard user agents
- Rate limit compliance
- Timeout handling

---

## 📈 Performance

- **Dashboard Load**: < 2 seconds
- **Data Collection**: 30-60 seconds (all 6 sources)
- **Analysis**: < 5 seconds for 100 threats
- **Memory**: ~50-100MB typical
- **Concurrent Users**: Supports multiple (Streamlit Cloud)

---

## 🐛 Troubleshooting

### Dashboard Issues

**Problem**: App won't start
```bash
# Solution: Check dependencies
pip install -r requirements_streamlit.txt --upgrade
```

**Problem**: No data showing
```bash
# Solution: Use Demo Data first
# Click "Demo Data" -> "Refresh Data" in sidebar
```

**Problem**: Live collection failing
```bash
# Normal on some networks/Streamlit Cloud
# Use Demo Data mode instead
```

### CLI Issues

**Problem**: Import errors
```bash
pip install -r requirements.txt --break-system-packages
```

**Problem**: No threats collected
```bash
# Check internet connection
# Try individual sources
python3 -c "import collectors; collectors.CISAFeedCollector().collect()"
```

---

## 🤝 Contributing

We welcome contributions!

### Add a Data Source
1. Create collector class in `collectors.py`
2. Add to `collect_all_threats()` function
3. Update documentation

### Improve MITRE Mapping
1. Add techniques to `mitre_mapping.py`
2. Include detection keywords
3. Test with sample data

### Enhance Dashboard
1. Edit `streamlit_app.py`
2. Add new charts or views
3. Update sidebar options

---

## 📚 Documentation

- **[STREAMLIT_DEPLOY.md](STREAMLIT_DEPLOY.md)** - Complete deployment guide
- **[QUICKSTART.md](QUICKSTART.md)** - Quick reference for CLI
- **[OVERVIEW.md](OVERVIEW.md)** - System architecture
- **[README.md](README.md)** - This file

---

## 🎓 Learning Resources

### MITRE ATT&CK
- [MITRE ATT&CK Website](https://attack.mitre.org/)
- Technique descriptions
- Tactic categories
- Real-world examples

### Threat Intelligence
- Data source documentation
- API references
- Best practices
- Analysis techniques

---

## 📝 License

This project is for educational and security research purposes.

---

## 🙏 Acknowledgments

### Data Sources
- CISA - US Cybersecurity & Infrastructure Security Agency
- NIST - National Vulnerability Database
- abuse.ch - ThreatFox and URLhaus
- AlienVault - Open Threat Exchange
- The Hacker News - Security news

### Frameworks
- MITRE ATT&CK Framework
- Streamlit for dashboard
- Plotly for visualizations

---

## 📧 Support

For issues, questions, or suggestions:
1. Check documentation first
2. Review troubleshooting section
3. Test with Demo Data
4. Check GitHub issues

---

## 🚀 Quick Command Reference

### Web Dashboard
```bash
streamlit run streamlit_app.py
```

### CLI Tools
```bash
# Full analysis
python3 threat_tracker.py

# Specific view
python3 threat_tracker.py --view actor

# Demo
python3 demo.py

# Query
python3 query_threats.py data/*.json --search ransomware
```

---

## ⭐ What's New

### v1.0 - Streamlit Dashboard
- ✨ Interactive web interface
- 📊 Real-time charts and visualizations
- 🎯 Multiple view modes
- 🔍 Search and filtering
- 📱 Mobile responsive design
- 🚀 One-click deployment

---

**Built by security engineers, for security engineers** 🛡️
