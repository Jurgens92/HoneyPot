"""Flask web application for the honeypot management backend (port 8080)."""

import ipaddress
from flask import Flask, render_template, request, redirect, url_for, jsonify, Response
import database as db
from honeypot_services import SERVICE_DEFINITIONS


def _is_valid_ip(value):
    """Return True if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

app = Flask(__name__)


@app.before_request
def _init():
    """Ensure DB is available for every request."""
    db.get_db()


@app.teardown_request
def _teardown(exc):
    db.close_db()


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    stats = db.get_stats()
    settings = {
        "auto_blacklist_threshold": db.get_setting("auto_blacklist_threshold", "10"),
        "auto_blacklist_window_minutes": db.get_setting("auto_blacklist_window_minutes", "5"),
        "published_list_type": db.get_setting("published_list_type", "blacklist"),
    }
    return render_template("dashboard.html", stats=stats, settings=settings)


# ---------------------------------------------------------------------------
# Connection logs
# ---------------------------------------------------------------------------

@app.route("/logs")
def logs():
    service = request.args.get("service")
    ip = request.args.get("ip")
    limit = int(request.args.get("limit", 200))
    entries = db.get_logs(limit=limit, service=service, ip=ip)
    services = [row["service"] for row in
                db.get_db().execute("SELECT DISTINCT service FROM connection_logs ORDER BY service").fetchall()]
    return render_template("logs.html", logs=entries, services=services,
                           current_service=service, current_ip=ip)


# ---------------------------------------------------------------------------
# IP management
# ---------------------------------------------------------------------------

@app.route("/blacklist")
def blacklist():
    ips = db.get_ips_with_services("blacklist")
    return render_template("ip_list.html", ips=ips, list_type="blacklist")


@app.route("/whitelist")
def whitelist():
    ips = db.get_ips_with_services("whitelist")
    return render_template("ip_list.html", ips=ips, list_type="whitelist")


@app.route("/ip/add", methods=["POST"])
def add_ip():
    ip = request.form.get("ip_address", "").strip()
    list_type = request.form.get("list_type", "blacklist")
    reason = request.form.get("reason", "").strip() or "Manually added"
    if ip and _is_valid_ip(ip):
        db.add_ip(ip, list_type, reason=reason)
    return redirect(url_for(list_type))


@app.route("/ip/remove", methods=["POST"])
def remove_ip():
    ip = request.form.get("ip_address", "").strip()
    redirect_to = request.form.get("redirect_to", "blacklist")
    if ip:
        db.remove_ip(ip)
    return redirect(url_for(redirect_to))


@app.route("/ip/move", methods=["POST"])
def move_ip():
    ip = request.form.get("ip_address", "").strip()
    new_list = request.form.get("new_list_type", "whitelist")
    if ip:
        db.move_ip(ip, new_list)
    return redirect(url_for(new_list))


# ---------------------------------------------------------------------------
# Services overview
# ---------------------------------------------------------------------------

@app.route("/services")
def services():
    svc_list = []
    for port, name, _handler in SERVICE_DEFINITIONS:
        count = db.get_db().execute(
            "SELECT COUNT(*) as cnt FROM connection_logs WHERE service = ? AND dest_port = ?",
            (name, port),
        ).fetchone()["cnt"]
        unique = db.get_db().execute(
            "SELECT COUNT(DISTINCT source_ip) as cnt FROM connection_logs WHERE service = ? AND dest_port = ?",
            (name, port),
        ).fetchone()["cnt"]
        last_row = db.get_db().execute(
            "SELECT timestamp FROM connection_logs WHERE service = ? AND dest_port = ? ORDER BY timestamp DESC LIMIT 1",
            (name, port),
        ).fetchone()
        svc_list.append({
            "name": name,
            "port": port,
            "connections": count,
            "unique_ips": unique,
            "last_seen": last_row["timestamp"][:19] if last_row else "Never",
        })
    return render_template("services.html", services=svc_list)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@app.route("/settings", methods=["POST"])
def save_settings():
    for key in ("auto_blacklist_threshold", "auto_blacklist_window_minutes",
                "published_list_type"):
        val = request.form.get(key)
        if val is not None:
            db.set_setting(key, val.strip())
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Published list  (accessible as /list.txt)
# ---------------------------------------------------------------------------

@app.route("/list.txt")
def published_list():
    ips = db.get_published_list()
    return Response("\n".join(ips) + "\n", mimetype="text/plain")


# ---------------------------------------------------------------------------
# API endpoints (JSON)
# ---------------------------------------------------------------------------

@app.route("/api/stats")
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/logs")
def api_logs():
    service = request.args.get("service")
    ip = request.args.get("ip")
    limit = int(request.args.get("limit", 200))
    entries = db.get_logs(limit=limit, service=service, ip=ip)
    return jsonify([dict(e) for e in entries])


@app.route("/api/ips")
def api_ips():
    list_type = request.args.get("list_type")
    entries = db.get_ips(list_type)
    return jsonify([dict(e) for e in entries])
