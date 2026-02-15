# Streamlit Deployment Guide

## 🚀 Quick Deploy to Streamlit Cloud

### Step 1: Upload to GitHub

1. Create a new repository on GitHub
2. Upload all files from the `threat_tracker` folder:
   ```bash
   git init
   git add .
   git commit -m "Initial commit - Threat Intelligence Tracker"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/threat-tracker.git
   git push -u origin main
   ```

### Step 2: Deploy on Streamlit Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Sign in with GitHub
3. Click "New app"
4. Select your repository: `YOUR_USERNAME/threat-tracker`
5. Set main file path: `streamlit_app.py`
6. Click "Deploy"

**That's it!** Your dashboard will be live in 2-3 minutes.

---

## 🏃 Run Locally

### Option 1: Quick Start
```bash
cd threat_tracker
pip install -r requirements_streamlit.txt
streamlit run streamlit_app.py
```

### Option 2: With Virtual Environment (Recommended)
```bash
cd threat_tracker

# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # On Mac/Linux
# or
venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r requirements_streamlit.txt

# Run the app
streamlit run streamlit_app.py
```

The app will open at: `http://localhost:8501`

---

## 📁 Required Files for Streamlit

Make sure your GitHub repository includes:

```
threat-tracker/
├── streamlit_app.py           ✅ Main Streamlit app
├── collectors.py              ✅ Data collectors
├── analyzer.py                ✅ Analysis engine
├── mitre_mapping.py           ✅ MITRE framework
├── demo.py                    ✅ Demo data generator
├── requirements_streamlit.txt ✅ Streamlit dependencies
└── README.md                  ✅ Documentation
```

**Note:** You do NOT need:
- `visualizer.py` (terminal-specific)
- `query_threats.py` (CLI tool)
- `threat_tracker.py` (CLI tool)
- Original `requirements.txt` (use `requirements_streamlit.txt` instead)

---

## ⚙️ Streamlit Configuration (Optional)

Create `.streamlit/config.toml` in your repo:

```toml
[theme]
primaryColor = "#1f77b4"
backgroundColor = "#ffffff"
secondaryBackgroundColor = "#f0f2f6"
textColor = "#262730"
font = "sans serif"

[server]
headless = true
port = 8501
enableCORS = false
```

---

## 🌐 Environment Variables (Optional)

If you want to add API keys later, create a `secrets.toml`:

```toml
# .streamlit/secrets.toml
# Add any API keys here (not needed for open sources)
```

---

## 🎯 Features in Streamlit Dashboard

### ✅ What Works:
- 📊 Interactive dashboard with live charts
- 🔄 Demo data mode (works immediately)
- 🌐 Live data collection (requires internet)
- ⚠️ Critical threat alerts
- 👥 Threat actor profiles
- 🎯 MITRE ATT&CK visualizations
- 🌍 Geographic threat maps
- 🔍 Search and filtering
- 📱 Mobile responsive
- 🎨 Professional UI with colors

### 📊 Available Views:
1. **Dashboard** - Overview with charts and metrics
2. **Critical Threats** - High-priority threats only
3. **Threat Actors** - APT group profiles
4. **Attack Vectors** - MITRE technique analysis
5. **Geographic** - Location-based threats
6. **All Threats** - Complete threat list with search

---

## 🐛 Troubleshooting

### Issue: App won't start
**Solution:** Check that all Python files are in the same directory

### Issue: No data showing
**Solution:** Click "Refresh Data" button in sidebar and select "Demo Data"

### Issue: Live collection failing
**Solution:** This is normal on Streamlit Cloud due to network restrictions. Use "Demo Data" mode instead.

### Issue: Charts not displaying
**Solution:** Make sure `plotly` is in requirements_streamlit.txt

---

## 🎨 Customization

### Change Colors
Edit the CSS in `streamlit_app.py` around line 30:
```python
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #YOUR_COLOR1 0%, #YOUR_COLOR2 100%);
    }
</style>
""", unsafe_allow_html=True)
```

### Add More Charts
Add new functions in `streamlit_app.py`:
```python
def create_your_chart(stats):
    df = pd.DataFrame(...)
    fig = px.bar(df, ...)
    return fig
```

### Modify Sidebar
Edit the sidebar section starting at line 150

---

## 📊 Data Sources

The dashboard collects from:
1. **CISA** - US Government alerts
2. **NVD** - CVE vulnerabilities  
3. **ThreatFox** - IOC database
4. **AlienVault OTX** - Threat exchange
5. **URLhaus** - Malicious URLs
6. **The Hacker News** - Security news

---

## 🔒 Security Notes

- App uses only public data sources
- No authentication required for demo mode
- Live collection may be restricted on some networks
- No sensitive data is stored
- All data is in-memory (resets on restart)

---

## 💡 Tips for Best Experience

1. **Start with Demo Data** - See the dashboard immediately
2. **Use Filters** - Narrow down by severity or source
3. **Explore Views** - Each view shows different insights
4. **Bookmark the URL** - Share with your team
5. **Refresh Regularly** - Get latest threat intelligence

---

## 📱 Mobile Support

The dashboard is responsive and works on:
- 📱 Phones
- 📱 Tablets  
- 💻 Desktops
- 🖥️ Large screens

---

## 🆘 Need Help?

1. Check the README.md for detailed documentation
2. Review the code comments in streamlit_app.py
3. Test locally first before deploying
4. Use Demo Data mode if Live Collection fails

---

## ✨ What's Next?

Once deployed, you can:
- ✅ Share the URL with your security team
- ✅ View real-time threat intelligence
- ✅ Export data for reports
- ✅ Customize for your needs
- ✅ Add more data sources
- ✅ Integrate with other tools

**Your threat intelligence dashboard is now ready! 🎉**
