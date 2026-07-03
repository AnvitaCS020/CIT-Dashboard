"""
VirusTotal API v3 handler.
Supports: IP lookup, domain lookup, URL lookup, file hash lookup.
"""

import requests
import config

BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": config.VIRUSTOTAL_API_KEY}


def _get(endpoint: str) -> dict:
    try:
        r = requests.get(f"{BASE}/{endpoint}", headers=HEADERS, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {r.status_code}: {r.text}"}
    except Exception as e:
        return {"error": str(e)}


def lookup_ip(ip: str) -> dict:
    data = _get(f"ip_addresses/{ip}")
    if "error" in data:
        return data
    attr = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "type": "ip",
        "indicator": ip,
        "malicious":   stats.get("malicious", 0),
        "suspicious":  stats.get("suspicious", 0),
        "harmless":    stats.get("harmless", 0),
        "undetected":  stats.get("undetected", 0),
        "country":     attr.get("country", "N/A"),
        "asn":         attr.get("asn", "N/A"),
        "as_owner":    attr.get("as_owner", "N/A"),
        "reputation":  attr.get("reputation", 0),
        "tags":        attr.get("tags", []),
        "raw":         attr,
    }


def lookup_domain(domain: str) -> dict:
    data = _get(f"domains/{domain}")
    if "error" in data:
        return data
    attr = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "type": "domain",
        "indicator": domain,
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "registrar":  attr.get("registrar", "N/A"),
        "creation_date": attr.get("creation_date", "N/A"),
        "reputation": attr.get("reputation", 0),
        "tags":       attr.get("tags", []),
        "raw":        attr,
    }


def lookup_url(url: str) -> dict:
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = _get(f"urls/{url_id}")
    if "error" in data:
        return data
    attr = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "type": "url",
        "indicator": url,
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "final_url":  attr.get("last_final_url", url),
        "title":      attr.get("title", "N/A"),
        "raw":        attr,
    }


def lookup_hash(file_hash: str) -> dict:
    data = _get(f"files/{file_hash}")
    if "error" in data:
        return data
    attr = data.get("data", {}).get("attributes", {})
    stats = attr.get("last_analysis_stats", {})
    return {
        "type": "hash",
        "indicator": file_hash,
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "name":       attr.get("meaningful_name", "N/A"),
        "size":       attr.get("size", 0),
        "type_desc":  attr.get("type_description", "N/A"),
        "tags":       attr.get("tags", []),
        "raw":        attr,
    }
