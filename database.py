"""SQLite database module for the honeypot application."""

import sqlite3
import os
import threading
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypot.db")

_local = threading.local()


def get_db():
    """Get a thread-local database connection."""
    if not hasattr(_local, "connection") or _local.connection is None:
        _local.connection = sqlite3.connect(DB_PATH)
        _local.connection.row_factory = sqlite3.Row
        _local.connection.execute("PRAGMA journal_mode=WAL")
        _local.connection.execute("PRAGMA foreign_keys=ON")
    return _local.connection


def close_db():
    """Close the thread-local database connection."""
    if hasattr(_local, "connection") and _local.connection is not None:
        _local.connection.close()
        _local.connection = None


def init_db():
    """Initialize the database schema."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS connection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            source_port INTEGER,
            service TEXT NOT NULL,
            dest_port INTEGER NOT NULL,
            details TEXT,
            username TEXT,
            password TEXT
        );

        CREATE TABLE IF NOT EXISTS ip_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            list_type TEXT NOT NULL CHECK(list_type IN ('blacklist', 'whitelist')),
            added_at TEXT NOT NULL,
            reason TEXT,
            auto_added INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON connection_logs(source_ip);
        CREATE INDEX IF NOT EXISTS idx_logs_service ON connection_logs(service);
        CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON connection_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_ip_list_type ON ip_list(list_type);
        CREATE INDEX IF NOT EXISTS idx_ip_list_address ON ip_list(ip_address);
    """)

    # Default settings
    defaults = {
        "auto_blacklist_threshold": "10",
        "auto_blacklist_window_minutes": "5",
        "published_list_type": "blacklist",
    }
    for key, value in defaults.items():
        db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )
    db.commit()


def log_connection(source_ip, source_port, service, dest_port, details=None,
                   username=None, password=None):
    """Log a connection attempt."""
    db = get_db()
    db.execute(
        """INSERT INTO connection_logs
           (timestamp, source_ip, source_port, service, dest_port, details, username, password)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (datetime.utcnow().isoformat(), source_ip, source_port, service,
         dest_port, details, username, password),
    )
    db.commit()

    # Check auto-blacklist threshold
    _check_auto_blacklist(source_ip)


def _check_auto_blacklist(ip):
    """Auto-blacklist an IP if it exceeds the threshold."""
    db = get_db()
    # Skip if already in any list
    row = db.execute(
        "SELECT id FROM ip_list WHERE ip_address = ?", (ip,)
    ).fetchone()
    if row:
        return

    threshold = int(get_setting("auto_blacklist_threshold", "10"))
    window = int(get_setting("auto_blacklist_window_minutes", "5"))

    count = db.execute(
        """SELECT COUNT(*) as cnt FROM connection_logs
           WHERE source_ip = ?
           AND timestamp >= datetime('now', ?)""",
        (ip, f"-{window} minutes"),
    ).fetchone()["cnt"]

    if count >= threshold:
        add_ip(ip, "blacklist", reason=f"Auto-blacklisted: {count} attempts in {window}min",
               auto_added=True)


def add_ip(ip, list_type, reason=None, auto_added=False):
    """Add an IP to the blacklist or whitelist."""
    db = get_db()
    try:
        db.execute(
            """INSERT INTO ip_list (ip_address, list_type, added_at, reason, auto_added)
               VALUES (?, ?, ?, ?, ?)""",
            (ip, list_type, datetime.utcnow().isoformat(), reason, int(auto_added)),
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def remove_ip(ip):
    """Remove an IP from any list."""
    db = get_db()
    db.execute("DELETE FROM ip_list WHERE ip_address = ?", (ip,))
    db.commit()


def move_ip(ip, new_list_type):
    """Move an IP between blacklist and whitelist."""
    db = get_db()
    db.execute(
        "UPDATE ip_list SET list_type = ? WHERE ip_address = ?",
        (new_list_type, ip),
    )
    db.commit()


def get_ips(list_type=None):
    """Get IPs, optionally filtered by list type."""
    db = get_db()
    if list_type:
        return db.execute(
            "SELECT * FROM ip_list WHERE list_type = ? ORDER BY added_at DESC",
            (list_type,),
        ).fetchall()
    return db.execute(
        "SELECT * FROM ip_list ORDER BY list_type, added_at DESC"
    ).fetchall()


def get_logs(limit=200, service=None, ip=None):
    """Get connection logs with optional filters."""
    db = get_db()
    query = "SELECT * FROM connection_logs WHERE 1=1"
    params = []
    if service:
        query += " AND service = ?"
        params.append(service)
    if ip:
        query += " AND source_ip = ?"
        params.append(ip)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    return db.execute(query, params).fetchall()


def get_stats():
    """Get dashboard statistics."""
    db = get_db()
    total_connections = db.execute(
        "SELECT COUNT(*) as cnt FROM connection_logs"
    ).fetchone()["cnt"]
    unique_ips = db.execute(
        "SELECT COUNT(DISTINCT source_ip) as cnt FROM connection_logs"
    ).fetchone()["cnt"]
    blacklisted = db.execute(
        "SELECT COUNT(*) as cnt FROM ip_list WHERE list_type = 'blacklist'"
    ).fetchone()["cnt"]
    whitelisted = db.execute(
        "SELECT COUNT(*) as cnt FROM ip_list WHERE list_type = 'whitelist'"
    ).fetchone()["cnt"]

    by_service = db.execute(
        """SELECT service, COUNT(*) as cnt FROM connection_logs
           GROUP BY service ORDER BY cnt DESC"""
    ).fetchall()

    top_ips = db.execute(
        """SELECT source_ip, COUNT(*) as cnt FROM connection_logs
           GROUP BY source_ip ORDER BY cnt DESC LIMIT 20"""
    ).fetchall()

    recent = db.execute(
        """SELECT * FROM connection_logs ORDER BY timestamp DESC LIMIT 50"""
    ).fetchall()

    return {
        "total_connections": total_connections,
        "unique_ips": unique_ips,
        "blacklisted": blacklisted,
        "whitelisted": whitelisted,
        "by_service": [dict(r) for r in by_service],
        "top_ips": [dict(r) for r in top_ips],
        "recent": [dict(r) for r in recent],
    }


def get_setting(key, default=None):
    """Get a setting value."""
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key, value):
    """Set a setting value."""
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
        (key, value),
    )
    db.commit()


def get_ip_services(ip):
    """Get the distinct services an IP was seen on, with connection counts."""
    db = get_db()
    return db.execute(
        """SELECT service, dest_port, COUNT(*) as cnt
           FROM connection_logs WHERE source_ip = ?
           GROUP BY service, dest_port ORDER BY cnt DESC""",
        (ip,),
    ).fetchall()


def get_ips_with_services(list_type):
    """Get IPs with their associated service/port breakdown."""
    ips = get_ips(list_type)
    result = []
    for ip_row in ips:
        ip_dict = dict(ip_row)
        services = get_ip_services(ip_dict["ip_address"])
        ip_dict["services"] = [
            {"service": s["service"], "port": s["dest_port"], "count": s["cnt"]}
            for s in services
        ]
        result.append(ip_dict)
    return result


def get_published_list():
    """Get the list of IPs to publish in list.txt."""
    db = get_db()
    list_type = get_setting("published_list_type", "blacklist")
    rows = db.execute(
        "SELECT ip_address FROM ip_list WHERE list_type = ? ORDER BY ip_address",
        (list_type,),
    ).fetchall()
    return [r["ip_address"] for r in rows]
