# CTI Dashboard 🛡️

A **Cyber Threat Intelligence Dashboard** built with Flask + SQLite.  
Combines VirusTotal, AbuseIPDB, and open threat feeds into a single dark-mode UI.

---

## Features

| Feature | Details |
|---|---|
| **Indicator Lookup** | IP · Domain · URL · File Hash |
| **VirusTotal** | Detection ratios, engine verdicts, metadata |
| **AbuseIPDB** | Abuse confidence score, ISP, recent reports |
| **Open Threat Feeds** | Emerging Threats, Feodo Tracker, URLhaus |
| **Auto Alerts** | Critical / High severity alerts generated automatically |
| **IOC Database** | SQLite store with full-text search & pagination |
| **Dashboard** | Stats, charts, recent alerts overview |
| **Lookup History** | Every query logged with source and timestamp |

---

## Prerequisites

- **Python 3.10+** (3.11 or 3.12 recommended)
- **pip** (comes with Python)
- Internet connection (to call APIs and download feeds)

---

## Quick Start

### 1. Unzip the project

```bash
unzip cti-dashboard.zip
cd cti-dashboard
```

### 2. Create a virtual environment

```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows (Command Prompt)
python -m venv venv
venv\Scripts\activate.bat

# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set your API keys

**Option A – Edit `config.py` directly** (easiest for local use):

```python
# config.py
VIRUSTOTAL_API_KEY = "your_vt_key_here"
ABUSEIPDB_API_KEY  = "your_abuseipdb_key_here"
```

**Option B – Environment variables** (recommended for production):

```bash
# macOS / Linux
export VIRUSTOTAL_API_KEY="your_vt_key_here"
export ABUSEIPDB_API_KEY="your_abuseipdb_key_here"

# Windows (Command Prompt)
set VIRUSTOTAL_API_KEY=your_vt_key_here
set ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

> **Get free API keys:**
> - VirusTotal: https://www.virustotal.com/gui/join-us
> - AbuseIPDB:  https://www.abuseipdb.com/register

### 5. Run the app

```bash
python app.py
```

Then open your browser at: **http://localhost:5000**

---

## Getting Started in the UI

1. **Dashboard** – Overview stats load automatically on launch.
2. **Indicator Lookup** – Enter any IP, domain, URL, or file hash and click **Analyze**.
3. **Threat Feeds** → Click **Refresh All Feeds** to pull the latest open-source block lists into the database (takes ~30 seconds).
4. **IOC Database** – Browse/search all ingested indicators.
5. **Alerts** – High-confidence detections appear here automatically after lookups.
6. **Lookup History** – Every query is logged here.

---

## Project Structure

```
cti-dashboard/
├── app.py              # Flask routes & API endpoints
├── config.py           # API keys, feed URLs, DB path
├── requirements.txt    # Python dependencies
├── modules/
│   ├── virustotal.py   # VirusTotal API v3 handler
│   ├── abuseipdb.py    # AbuseIPDB API v2 handler
│   └── threat_feed.py  # Open feed downloader & parser
├── templates/
│   └── index.html      # Single-page dashboard UI
├── static/
│   └── style.css       # Dark-mode CSS
└── database/
    └── threats.db      # SQLite database (auto-created)
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET  | `/` | Dashboard UI |
| GET  | `/api/stats` | Summary statistics |
| POST | `/api/lookup` | Analyze an indicator (`{"indicator": "..."}`) |
| GET  | `/api/alerts` | List all alerts |
| POST | `/api/alerts/<id>/resolve` | Resolve an alert |
| GET  | `/api/iocs?page=1&per=50&q=` | Paginated IOC list |
| GET  | `/api/history?limit=50` | Lookup history |
| POST | `/api/feeds/refresh` | Pull latest threat feeds |
| GET  | `/api/feeds/stats` | Feed indicator counts |

---

## Configuration Reference

```python
# config.py

VIRUSTOTAL_API_KEY = "..."      # VirusTotal API key
ABUSEIPDB_API_KEY  = "..."      # AbuseIPDB API key

THREAT_FEEDS = {                # Add/remove open feeds here
    "Emerging Threats": "https://...",
    "Feodo Tracker":    "https://...",
}

DATABASE_PATH = "database/threats.db"
PORT = 5000
DEBUG = True
```

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `ModuleNotFoundError: flask` | Run `pip install -r requirements.txt` with your venv activated |
| API returns `401 Unauthorized` | Check your API keys in `config.py` |
| Feeds timeout | Normal for large feeds — wait up to 60 seconds |
| Port 5000 already in use | Change `PORT = 5001` in `config.py` |
| `database` folder missing | Create it: `mkdir database` |

---

## Notes

- The SQLite database (`database/threats.db`) is created automatically on first run.
- Free VirusTotal API: 4 lookups/min, 500/day.
- Free AbuseIPDB API: 1,000 checks/day.
- Open threat feeds require no authentication.
- All data stays local — nothing is sent anywhere except to the official APIs.

---

## License

MIT — free to use and modify.
