# 🚀 Deployment Checklist - GitHub → Streamlit

## ✅ Pre-Deployment Checklist

### Files to Include in GitHub Repository

```
✓ streamlit_app.py              (Main dashboard - REQUIRED)
✓ collectors.py                 (Data collectors - REQUIRED)
✓ analyzer.py                   (Analysis engine - REQUIRED)
✓ mitre_mapping.py              (MITRE framework - REQUIRED)
✓ demo.py                       (Demo data - REQUIRED)
✓ requirements_streamlit.txt    (Dependencies - REQUIRED)
✓ README.md                     (Documentation - RECOMMENDED)
✓ STREAMLIT_DEPLOY.md           (Deploy guide - RECOMMENDED)
✓ .streamlit/config.toml        (Config - OPTIONAL)

✗ visualizer.py                 (Terminal only - NOT NEEDED)
✗ query_threats.py              (CLI tool - NOT NEEDED)
✗ threat_tracker.py             (CLI tool - NOT NEEDED)
✗ requirements.txt              (CLI deps - NOT NEEDED)
```

### Minimum Files Needed
Just need these 6 files:
1. streamlit_app.py
2. collectors.py
3. analyzer.py
4. mitre_mapping.py
5. demo.py
6. requirements_streamlit.txt

---

## 📝 Step-by-Step: GitHub Upload

### Method 1: GitHub Web Interface (Easiest)

1. **Create Repository**
   - Go to github.com
   - Click "New repository"
   - Name: `threat-tracker` (or your choice)
   - Make it Public
   - Click "Create repository"

2. **Upload Files**
   - Click "uploading an existing file"
   - Drag and drop these files:
     - streamlit_app.py
     - collectors.py
     - analyzer.py
     - mitre_mapping.py
     - demo.py
     - requirements_streamlit.txt
     - README.md
   - Click "Commit changes"

3. **Done!** Your repo is ready

### Method 2: Git Command Line

```bash
cd threat_tracker

# Initialize git
git init

# Add files
git add streamlit_app.py collectors.py analyzer.py mitre_mapping.py demo.py requirements_streamlit.txt README.md STREAMLIT_DEPLOY.md

# Commit
git commit -m "Initial commit - Threat Intelligence Dashboard"

# Add remote (replace YOUR_USERNAME)
git remote add origin https://github.com/YOUR_USERNAME/threat-tracker.git

# Push
git branch -M main
git push -u origin main
```

---

## 🌐 Step-by-Step: Streamlit Cloud Deployment

### 1. Go to Streamlit Cloud
Visit: https://share.streamlit.io

### 2. Sign In
- Click "Sign in"
- Choose "Continue with GitHub"
- Authorize Streamlit

### 3. Deploy New App
- Click "New app" (big button)
- Or click "Create app" if you have existing apps

### 4. Configure Deployment

**Repository Settings:**
- Repository: `YOUR_USERNAME/threat-tracker`
- Branch: `main`
- Main file path: `streamlit_app.py`

**App URL (Optional):**
- Choose your app's URL
- Example: `threat-tracker-yourname.streamlit.app`

### 5. Deploy!
- Click "Deploy"
- Wait 2-3 minutes
- Watch the build logs
- **Done!** Your app is live

### 6. Test Your Dashboard
- Click "Refresh Data" in sidebar
- Select "Demo Data"
- Click the refresh button
- See your dashboard populate with threats!

---

## 🎯 Post-Deployment Testing

### Test Checklist

1. **Dashboard Loads**
   - [ ] App opens without errors
   - [ ] Sidebar visible
   - [ ] Main content area shows welcome message

2. **Demo Data Works**
   - [ ] Select "Demo Data" in sidebar
   - [ ] Click "Refresh Data"
   - [ ] Success message appears
   - [ ] Charts and metrics populate

3. **All Views Work**
   - [ ] Dashboard view shows charts
   - [ ] Critical Threats shows alerts
   - [ ] Threat Actors shows profiles
   - [ ] Attack Vectors shows techniques
   - [ ] Geographic shows location data
   - [ ] All Threats shows list

4. **Filters Work**
   - [ ] Severity filter reduces results
   - [ ] Source filter works
   - [ ] Search finds threats

5. **Interactive Elements**
   - [ ] Expandable cards work
   - [ ] Charts are interactive
   - [ ] Links are clickable

---

## 🐛 Common Issues & Solutions

### Issue: App won't deploy
**Cause:** Missing dependencies
**Solution:** Check `requirements_streamlit.txt` is uploaded and contains:
```
streamlit==1.31.0
plotly==5.18.0
pandas==2.1.3
requests==2.31.0
feedparser==6.0.10
beautifulsoup4==4.12.2
python-dateutil==2.8.2
lxml==4.9.3
```

### Issue: Import errors
**Cause:** Missing Python files
**Solution:** Ensure all required files are in root directory:
- streamlit_app.py
- collectors.py
- analyzer.py
- mitre_mapping.py
- demo.py

### Issue: No data showing
**Cause:** Didn't click refresh
**Solution:** 
1. Select "Demo Data" in sidebar
2. Click "Refresh Data" button
3. Wait for success message

### Issue: Live collection fails
**Cause:** Network restrictions on Streamlit Cloud
**Solution:** This is NORMAL. Always use "Demo Data" mode on Streamlit Cloud.

### Issue: Charts not displaying
**Cause:** Plotly not installed
**Solution:** Add `plotly==5.18.0` to requirements_streamlit.txt

---

## 🔄 Updating Your Deployed App

### Update Code
1. Edit files in your GitHub repository
2. Commit changes
3. Push to GitHub
4. Streamlit auto-deploys (within 1 minute)

### Manual Redeploy
1. Go to share.streamlit.io
2. Click on your app
3. Click "⋮" (three dots menu)
4. Select "Reboot app"

---

## 🎨 Customization After Deploy

### Change App Title
Edit `streamlit_app.py` line ~35:
```python
st.set_page_config(
    page_title="YOUR CUSTOM TITLE",
    page_icon="🛡️",
)
```

### Change Colors
Edit CSS in `streamlit_app.py` around line 40:
```python
.main-header {
    background: linear-gradient(90deg, #YOUR_COLOR1 0%, #YOUR_COLOR2 100%);
}
```

### Add Your Logo
Edit sidebar section around line 150:
```python
st.image("YOUR_LOGO_URL", width=100)
```

---

## 📊 Usage Tips

### For Best Results:
1. **Always use Demo Data** on Streamlit Cloud (Live collection may be blocked)
2. **Bookmark the URL** for quick access
3. **Share with team** - Public apps work for everyone
4. **Refresh periodically** - Demo data is randomized each time
5. **Explore all views** - Each shows different insights

### Recommended Workflow:
1. Open dashboard
2. Click "Refresh Data" with Demo Data
3. Start with Dashboard view (overview)
4. Check Critical Threats view (priorities)
5. Explore Threat Actors (attribution)
6. Review Attack Vectors (techniques)
7. Check Geographic (locations)

---

## 🔒 Privacy & Security

### What's Stored:
- **Nothing persistent** - All data in-memory
- **No user data** - No tracking or analytics
- **No secrets** - Uses only public APIs
- **No authentication** - Fully public

### What's Collected (by Streamlit):
- Basic usage analytics (if enabled)
- Error logs for debugging
- App performance metrics

### What's NOT Collected:
- User credentials
- Personal information
- Uploaded files (we don't allow uploads)
- Sensitive data

---

## 💡 Pro Tips

### Performance
- Demo data loads instantly
- Live collection takes 30-60 seconds
- Cache refreshes on page reload
- No persistent storage needed

### Sharing
- URL works for everyone
- No login required
- Mobile-friendly
- Works in all browsers

### Customization
- All code is editable
- Add more data sources in collectors.py
- Add charts in streamlit_app.py
- Modify filters and views

---

## 📚 Resources

### Documentation
- Streamlit Docs: https://docs.streamlit.io
- Plotly Docs: https://plotly.com/python
- GitHub Docs: https://docs.github.com

### Your Files
- README.md - Full documentation
- STREAMLIT_DEPLOY.md - This deployment guide
- OVERVIEW.md - Architecture details

### Support
- Streamlit Community: https://discuss.streamlit.io
- GitHub Issues: Create in your repo

---

## ✅ Final Checklist

Before going live:
- [ ] All files uploaded to GitHub
- [ ] requirements_streamlit.txt has correct dependencies
- [ ] App deployed on Streamlit Cloud
- [ ] Tested Demo Data functionality
- [ ] All views working
- [ ] No console errors
- [ ] Shared URL with team
- [ ] Bookmarked dashboard

**Your threat intelligence dashboard is ready! 🎉**

---

## 🎓 Next Steps

After successful deployment:
1. ✅ Test all features
2. ✅ Share with your security team
3. ✅ Customize colors/branding
4. ✅ Add more data sources if needed
5. ✅ Star the repo on GitHub
6. ✅ Share your success!

**Happy threat hunting! 🔍🛡️**
