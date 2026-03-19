# AuthScan — Authentication Component Detector

## Folder Structure

```
authscan_final/
├── api/
│   └── index.py        ← Flask app (works locally + on Vercel)
├── templates/
│   └── index.html      ← Frontend UI
├── requirements.txt
└── vercel.json         ← Vercel deployment config
```

---

## Run Locally

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the app
python api/index.py

# 3. Open browser
http://127.0.0.1:5000
```

---

## Deploy to Vercel

### Option A — GitHub + Vercel Dashboard (easiest)

1. Push this folder to a GitHub repo:
   ```bash
   git init
   git add .
   git commit -m "initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/authscan.git
   git push -u origin main
   ```

2. Go to https://vercel.com → New Project → Import your repo → Deploy

3. Done! You get a live URL like https://authscan.vercel.app

### Option B — Vercel CLI (no GitHub needed)

```bash
# Install Vercel CLI once
npm install -g vercel

# Inside this folder
vercel

# Follow prompts → get live URL instantly
```

---

## Notes
- Vercel free tier has a 10s function timeout — slow sites may time out
- Sites that render login forms via JavaScript may show "Not Found"
