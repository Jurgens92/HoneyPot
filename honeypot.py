#!/usr/bin/env python3
"""
HoneyPot - A Flask-based honeypot application with fake services.

Fake services listen on: 80, 443, 22, 23, 8443, 25, 1433, 1434, 3306
Management backend runs on: 8080

Run as root (required for binding to privileged ports < 1024):
    sudo python3 honeypot.py
"""

import logging
import signal
import sys

from database import init_db, close_db
from honeypot_services import start_all_services, stop_all_services
from webapp import app

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("honeypot.log"),
    ],
)
logger = logging.getLogger("honeypot")

services = []


def shutdown(signum, frame):
    logger.info("Shutting down honeypot services...")
    stop_all_services(services)
    close_db()
    sys.exit(0)


def main():
    global services

    logger.info("Initializing HoneyPot database...")
    init_db()

    logger.info("Starting honeypot services...")
    services = start_all_services()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("Starting management web interface on http://0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080, threaded=True)


if __name__ == "__main__":
    main()
