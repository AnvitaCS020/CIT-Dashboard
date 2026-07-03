"""
AbuseIPDB API v2 handler.
Checks IP reputation and fetches recent abuse reports.
"""

import requests
import config

BASE    = "https://api.abuseipdb.com/api/v2"
HEADERS = {
    "Key":    config.ABUSEIPDB_API_KEY,
    "Accept": "application/json",
}


def check_ip(ip: str, max_age_days: int = 90) -> dict:
    """Return abuse-confidence score and metadata for an IP."""
    try:
        r = requests.get(
            f"{BASE}/check",
            headers=HEADERS,
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True},
            timeout=10,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "type":               "ip",
            "indicator":          ip,
            "abuse_score":        d.get("abuseConfidenceScore", 0),
            "country":            d.get("countryCode", "N/A"),
            "isp":                d.get("isp", "N/A"),
            "domain":             d.get("domain", "N/A"),
            "total_reports":      d.get("totalReports", 0),
            "last_reported":      d.get("lastReportedAt", "Never"),
            "is_whitelisted":     d.get("isWhitelisted", False),
            "is_tor":             d.get("isTor", False),
            "usage_type":         d.get("usageType", "N/A"),
            "recent_reports":     _parse_reports(d.get("reports", [])),
            "raw":                d,
        }
    except Exception as e:
        return {"error": str(e)}


def _parse_reports(reports: list) -> list:
    """Return the 5 most recent report summaries."""
    out = []
    for rep in reports[:5]:
        out.append({
            "reported_at":    rep.get("reportedAt"),
            "comment":        rep.get("comment", ""),
            "categories":     rep.get("categories", []),
            "reporter_country": rep.get("reporterCountryCode", "N/A"),
        })
    return out


# ── Category code → human label ──────────────────────────────────────────────
CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}

def category_label(code: int) -> str:
    return CATEGORIES.get(code, f"Category {code}")
