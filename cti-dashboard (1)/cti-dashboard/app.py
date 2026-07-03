"""
CTI Dashboard – Flask Backend
"""

import sqlite3
import ipaddress
import re
from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify
import config
from modules import virustotal, abuseipdb, threat_feed

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ── Database bootstrap ────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(config.DATABASE_PATH)
    cur  = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS threat_indicators (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator   TEXT    UNIQUE NOT NULL,
            type        TEXT    NOT NULL,
            source      TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            tags        TEXT
        );

        CREATE TABLE IF NOT EXISTS lookup_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator   TEXT NOT NULL,
            type        TEXT NOT NULL,
            source      TEXT NOT NULL,
            result_json TEXT,
            queried_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator   TEXT NOT NULL,
            severity    TEXT NOT NULL,
            message     TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            resolved    INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()


init_db()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detect_type(indicator: str) -> str:
    indicator = indicator.strip()
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^[a-fA-F0-9]{32,64}$", indicator):
        return "hash"
    if re.match(r"^https?://", indicator, re.I):
        return "url"
    if "." in indicator:
        return "domain"
    return "unknown"


def _save_history(indicator, itype, source, result):
    import json
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.execute(
        "INSERT INTO lookup_history (indicator, type, source, result_json) VALUES (?,?,?,?)",
        (indicator, itype, source, json.dumps(result)),
    )
    conn.commit()
    conn.close()


def _raise_alert_if_needed(indicator, result, source):
    severity = None
    message  = ""
    if source == "virustotal":
        mal = result.get("malicious", 0)
        if mal >= 10:
            severity, message = "critical", f"VT: {mal} engines flagged as malicious."
        elif mal >= 3:
            severity, message = "high",     f"VT: {mal} engines flagged as malicious."
    elif source == "abuseipdb":
        score = result.get("abuse_score", 0)
        if score >= 80:
            severity, message = "critical", f"AbuseIPDB score: {score}/100."
        elif score >= 40:
            severity, message = "high",     f"AbuseIPDB score: {score}/100."

    if severity:
        conn = sqlite3.connect(config.DATABASE_PATH)
        conn.execute(
            "INSERT INTO alerts (indicator, severity, message) VALUES (?,?,?)",
            (indicator, severity, message),
        )
        conn.commit()
        conn.close()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# Dashboard stats
@app.route("/api/stats")
def api_stats():
    conn = sqlite3.connect(config.DATABASE_PATH)
    cur  = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM threat_indicators")
    total_iocs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM lookup_history")
    total_lookups = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE resolved=0")
    open_alerts = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical' AND resolved=0")
    critical_alerts = cur.fetchone()[0]

    cur.execute("""
        SELECT type, COUNT(*) FROM threat_indicators GROUP BY type
    """)
    type_breakdown = {row[0]: row[1] for row in cur.fetchall()}

    cur.execute("""
        SELECT source, COUNT(*) FROM threat_indicators GROUP BY source ORDER BY COUNT(*) DESC
    """)
    source_breakdown = {row[0]: row[1] for row in cur.fetchall()}

    # Recent 7-day lookup activity
    cur.execute("""
        SELECT DATE(queried_at), COUNT(*)
        FROM lookup_history
        WHERE queried_at >= DATE('now', '-6 days')
        GROUP BY DATE(queried_at)
        ORDER BY DATE(queried_at)
    """)
    daily_lookups = {row[0]: row[1] for row in cur.fetchall()}

    conn.close()
    return jsonify({
        "total_iocs":       total_iocs,
        "total_lookups":    total_lookups,
        "open_alerts":      open_alerts,
        "critical_alerts":  critical_alerts,
        "type_breakdown":   type_breakdown,
        "source_breakdown": source_breakdown,
        "daily_lookups":    daily_lookups,
    })


# Indicator lookup
@app.route("/api/lookup", methods=["POST"])
def api_lookup():
    body      = request.get_json(force=True)
    indicator = (body.get("indicator") or "").strip()
    if not indicator:
        return jsonify({"error": "No indicator provided."}), 400

    itype  = _detect_type(indicator)
    result = {"indicator": indicator, "type": itype, "sources": {}}

    # VirusTotal
    if itype == "ip":
        vt = virustotal.lookup_ip(indicator)
    elif itype == "domain":
        vt = virustotal.lookup_domain(indicator)
    elif itype == "url":
        vt = virustotal.lookup_url(indicator)
    elif itype == "hash":
        vt = virustotal.lookup_hash(indicator)
    else:
        vt = {"error": "Unknown indicator type."}

    result["sources"]["virustotal"] = vt
    if "error" not in vt:
        _save_history(indicator, itype, "virustotal", vt)
        _raise_alert_if_needed(indicator, vt, "virustotal")

    # AbuseIPDB (IPs only)
    if itype == "ip":
        ab = abuseipdb.check_ip(indicator)
        result["sources"]["abuseipdb"] = ab
        if "error" not in ab:
            _save_history(indicator, itype, "abuseipdb", ab)
            _raise_alert_if_needed(indicator, ab, "abuseipdb")

    # Local feed check
    feed_hits = threat_feed.search_feeds(indicator)
    result["sources"]["local_feeds"] = feed_hits

    return jsonify(result)


# Recent lookups
@app.route("/api/history")
def api_history():
    limit = int(request.args.get("limit", 20))
    conn  = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur   = conn.cursor()
    cur.execute(
        "SELECT id, indicator, type, source, queried_at FROM lookup_history ORDER BY queried_at DESC LIMIT ?",
        (limit,),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


# Alerts
@app.route("/api/alerts")
def api_alerts():
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur  = conn.cursor()
    cur.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
def resolve_alert(alert_id):
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.execute("UPDATE alerts SET resolved=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


# Threat feed management
@app.route("/api/feeds/refresh", methods=["POST"])
def refresh_feeds():
    summary = threat_feed.refresh_feeds()
    return jsonify({"ok": True, "summary": summary})


@app.route("/api/feeds/stats")
def feed_stats():
    return jsonify(threat_feed.get_feed_stats())


# IOC list (paginated)
@app.route("/api/iocs")
def api_iocs():
    page    = int(request.args.get("page", 1))
    per     = int(request.args.get("per", 50))
    q       = request.args.get("q", "")
    offset  = (page - 1) * per

    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cur  = conn.cursor()

    if q:
        cur.execute(
            "SELECT * FROM threat_indicators WHERE indicator LIKE ? ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            (f"%{q}%", per, offset),
        )
    else:
        cur.execute(
            "SELECT * FROM threat_indicators ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            (per, offset),
        )

    rows = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT COUNT(*) FROM threat_indicators" + (" WHERE indicator LIKE ?" if q else ""),
                (f"%{q}%",) if q else ())
    total = cur.fetchone()[0]
    conn.close()
    return jsonify({"iocs": rows, "total": total, "page": page, "per": per})


if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
