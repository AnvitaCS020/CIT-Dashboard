import os

# ── API Keys ──────────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VT_API_KEY_HERE")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY",  "YOUR_ABUSEIPDB_API_KEY_HERE")

# ── Open Threat Feeds (no auth required) ─────────────────────────────────────
THREAT_FEEDS = {
    "Emerging Threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "Feodo Tracker":    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "URLhaus":          "https://urlhaus.abuse.ch/downloads/text/",
}

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_PATH = os.path.join(os.path.dirname(__file__), "database", "threats.db")

# ── Flask ─────────────────────────────────────────────────────────────────────
SECRET_KEY  = os.getenv("SECRET_KEY", "change-me-in-production")
DEBUG       = os.getenv("FLASK_DEBUG", "true").lower() == "true"
HOST        = "0.0.0.0"
PORT        = int(os.getenv("PORT", 5000))
