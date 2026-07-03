"""
Open-source CTI feed parser.
Downloads and parses plain-text IP/URL block lists.
"""

import re
import sqlite3
import requests
from datetime import datetime
import config

IP_RE  = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def _fetch_lines(url: str) -> list[str]:
    """Download a text feed and return non-comment, non-empty lines."""
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": "CTI-Dashboard/1.0"})
        r.raise_for_status()
        return [
            ln.strip()
            for ln in r.text.splitlines()
            if ln.strip() and not ln.startswith("#")
        ]
    except Exception as e:
        print(f"[threat_feed] Failed to fetch {url}: {e}")
        return []


def refresh_feeds(db_path: str = config.DATABASE_PATH) -> dict:
    """
    Pull all configured feeds and upsert indicators into the DB.
    Returns a summary dict.
    """
    conn  = sqlite3.connect(db_path)
    cur   = conn.cursor()
    summary = {}

    for feed_name, url in config.THREAT_FEEDS.items():
        lines = _fetch_lines(url)
        count = 0
        for indicator in lines:
            itype = _classify(indicator)
            if not itype:
                continue
            cur.execute(
                """
                INSERT INTO threat_indicators
                    (indicator, type, source, first_seen, last_seen, tags)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    source    = excluded.source
                """,
                (
                    indicator, itype, feed_name,
                    datetime.utcnow().isoformat(),
                    datetime.utcnow().isoformat(),
                    feed_name,
                ),
            )
            count += 1
        conn.commit()
        summary[feed_name] = count
        print(f"[threat_feed] {feed_name}: {count} indicators ingested.")

    conn.close()
    return summary


def _classify(indicator: str) -> str | None:
    if IP_RE.match(indicator):
        return "ip"
    if URL_RE.match(indicator):
        return "url"
    # bare domain heuristic
    if "." in indicator and "/" not in indicator and len(indicator) < 255:
        return "domain"
    return None


def search_feeds(query: str, db_path: str = config.DATABASE_PATH) -> list[dict]:
    """Return all feed entries whose indicator contains `query`."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur  = conn.cursor()
    cur.execute(
        "SELECT * FROM threat_indicators WHERE indicator LIKE ? ORDER BY last_seen DESC LIMIT 100",
        (f"%{query}%",),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_feed_stats(db_path: str = config.DATABASE_PATH) -> dict:
    """Return per-source indicator counts."""
    conn = sqlite3.connect(db_path)
    cur  = conn.cursor()
    cur.execute(
        "SELECT source, COUNT(*) AS cnt FROM threat_indicators GROUP BY source ORDER BY cnt DESC"
    )
    stats = {row[0]: row[1] for row in cur.fetchall()}
    conn.close()
    return stats
