#!/usr/bin/env python3
"""
HoneyPot - A Flask-based honeypot application with fake services.

Fake services listen on: 80, 443, 22, 23, 3389, 25, 1433, 1434, 3306
Management backend runs on: https://0.0.0.0:8080

Run as root (required for binding to privileged ports < 1024):
    sudo python3 honeypot.py
"""

import logging
import os
import signal
import ssl
import sys

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

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

    # Generate self-signed SSL certificate if not already present
    cert_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert.pem")
    key_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "key.pem")

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logger.info("Generating self-signed SSL certificate for HTTPS backend...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "HoneyPot Management"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        logger.info("SSL certificate generated: %s, %s", cert_file, key_file)

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(cert_file, key_file)

    logger.info("Starting management web interface on https://0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080, threaded=True, ssl_context=ssl_ctx)


if __name__ == "__main__":
    main()
