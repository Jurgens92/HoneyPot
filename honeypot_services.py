"""Fake honeypot services that listen on various ports and log connection attempts."""

import socket
import ssl
import threading
import logging
import os
import time

import paramiko

from database import log_connection, get_db, close_db

logger = logging.getLogger("honeypot")

# SSH host key (generated at startup if missing)
SSH_HOST_KEY_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "certs", "ssh_host_rsa_key"
)

TELNET_BANNER = b"\r\nUbuntu 22.04.3 LTS\r\n"
SMTP_BANNER = b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"
MYSQL_GREETING = (
    b"\x4a\x00\x00\x00\x0a"
    b"5.7.42-0ubuntu0.22.04.1\x00"
    b"\x01\x00\x00\x00"
    b"abcdefgh\x00"
    b"\xff\xf7"
    b"\x21"
    b"\x02\x00"
    b"\xff\x81"
    b"\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"ijklmnopqrst\x00"
    b"mysql_native_password\x00"
)
MSSQL_PRELOGIN_RESPONSE = (
    b"\x04\x01\x00\x25\x00\x00\x01\x00"
    b"\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x01\x03\x00\x1d\x00\x00\xff"
    b"\x10\x00\x06\x28\x00\x00\x01\x01\x00"
)

# Fake HTML login page
FAKE_LOGIN_HTML = b"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
Server: Apache/2.4.54 (Ubuntu)\r
Connection: close\r
\r
<!DOCTYPE html>
<html>
<head>
    <title>Portal Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f2f5; display: flex;
               justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 8px;
                     box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }
        h2 { text-align: center; color: #1a73e8; margin-bottom: 30px; }
        input { width: 100%%; padding: 12px; margin: 8px 0; border: 1px solid #ddd;
                border-radius: 4px; box-sizing: border-box; font-size: 14px; }
        button { width: 100%%; padding: 12px; background: #1a73e8; color: white;
                 border: none; border-radius: 4px; cursor: pointer; font-size: 16px;
                 margin-top: 15px; }
        button:hover { background: #1557b0; }
        .error { color: red; text-align: center; margin-top: 10px; display: none; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Secure Portal</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <p class="error" id="err">Invalid credentials. Please try again.</p>
    </div>
</body>
</html>
"""

FAKE_LOGIN_FAIL_HTML = b"""HTTP/1.1 200 OK\r
Content-Type: text/html\r
Server: Apache/2.4.54 (Ubuntu)\r
Connection: close\r
\r
<!DOCTYPE html>
<html>
<head>
    <title>Portal Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f2f5; display: flex;
               justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 8px;
                     box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 350px; }
        h2 { text-align: center; color: #1a73e8; margin-bottom: 30px; }
        input { width: 100%%; padding: 12px; margin: 8px 0; border: 1px solid #ddd;
                border-radius: 4px; box-sizing: border-box; font-size: 14px; }
        button { width: 100%%; padding: 12px; background: #1a73e8; color: white;
                 border: none; border-radius: 4px; cursor: pointer; font-size: 16px;
                 margin-top: 15px; }
        button:hover { background: #1557b0; }
        .error { color: red; text-align: center; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Secure Portal</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <p class="error">Invalid credentials. Please try again.</p>
    </div>
</body>
</html>
"""

# Self-signed cert paths (generated at startup if missing)
CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE = os.path.join(CERT_DIR, "server.key")


def _ensure_self_signed_cert():
    """Generate a self-signed certificate for the HTTPS honeypot if it doesn't exist."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    os.makedirs(CERT_DIR, exist_ok=True)
    import subprocess
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", KEY_FILE, "-out", CERT_FILE,
        "-days", "3650", "-nodes",
        "-subj", "/CN=portal.example.com/O=Example Corp/C=US",
    ], check=True, capture_output=True)
    logger.info("Generated self-signed certificate for HTTPS honeypot")


def _parse_http_post(data):
    """Extract username and password from an HTTP POST body."""
    try:
        body = data.split(b"\r\n\r\n", 1)[-1].decode("utf-8", errors="replace")
        params = {}
        for pair in body.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = v.replace("+", " ").strip()
        return params.get("username"), params.get("password")
    except Exception:
        return None, None


class HoneypotService(threading.Thread):
    """Base class for honeypot service threads."""

    def __init__(self, port, service_name, handler):
        super().__init__(daemon=True)
        self.port = port
        self.service_name = service_name
        self.handler = handler
        self._stop_event = threading.Event()

    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("0.0.0.0", self.port))
        except PermissionError:
            logger.error("Permission denied binding to port %d for %s "
                         "(try running as root)", self.port, self.service_name)
            return
        except OSError as e:
            logger.error("Cannot bind to port %d for %s: %s",
                         self.port, self.service_name, e)
            return
        server.listen(5)
        server.settimeout(1.0)
        logger.info("Honeypot service '%s' listening on port %d",
                     self.service_name, self.port)

        while not self._stop_event.is_set():
            try:
                client, addr = server.accept()
                t = threading.Thread(target=self._safe_handle,
                                     args=(client, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break
        server.close()

    def _safe_handle(self, client, addr):
        try:
            self.handler(client, addr, self.service_name, self.port)
        except Exception as e:
            logger.debug("Error handling %s connection from %s: %s",
                         self.service_name, addr, e)
        finally:
            try:
                client.close()
            except Exception:
                pass
            close_db()

    def stop(self):
        self._stop_event.set()


# ---------------------------------------------------------------------------
# Individual service handlers
# ---------------------------------------------------------------------------

def _ensure_ssh_host_key():
    """Generate an RSA host key for the fake SSH server if it doesn't exist."""
    os.makedirs(os.path.dirname(SSH_HOST_KEY_FILE), exist_ok=True)
    if os.path.exists(SSH_HOST_KEY_FILE):
        return paramiko.RSAKey(filename=SSH_HOST_KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(SSH_HOST_KEY_FILE)
    logger.info("Generated SSH host key for honeypot")
    return key


class _HoneypotSSHServer(paramiko.ServerInterface):
    """Paramiko server interface that accepts any credentials and logs them."""

    def __init__(self, addr, service_name, port):
        self.addr = addr
        self.service_name = service_name
        self.port = port
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_connection(self.addr[0], self.addr[1], self.service_name, self.port,
                       username=username, password=password,
                       details="SSH password auth")
        # Always deny so the attacker keeps trying
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log_connection(self.addr[0], self.addr[1], self.service_name, self.port,
                       username=username,
                       details=f"SSH pubkey auth ({key.get_name()})")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True


def handle_ssh(client, addr, service_name, port):
    """Fake SSH server using paramiko - lets attackers attempt real logins."""
    host_key = _ensure_ssh_host_key()
    transport = paramiko.Transport(client)
    transport.add_server_key(host_key)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

    server = _HoneypotSSHServer(addr, service_name, port)
    try:
        transport.start_server(server=server)
    except (paramiko.SSHException, EOFError, ConnectionResetError) as e:
        log_connection(addr[0], addr[1], service_name, port,
                       details=f"SSH handshake failed: {e}")
        return

    # Keep the transport open to allow multiple auth attempts (up to 60s)
    for _ in range(60):
        if not transport.is_active():
            break
        time.sleep(1)

    transport.close()


def _telnet_read_line(client, echo=True):
    """Read a line from a telnet client, byte by byte, with optional echo."""
    buf = b""
    while True:
        byte = client.recv(1)
        if not byte:
            return None
        # Ignore telnet IAC negotiation sequences
        if byte == b"\xff":
            client.recv(2)
            continue
        if byte in (b"\r", b"\n"):
            if echo:
                client.sendall(b"\r\n")
            # Consume trailing \n after \r if present
            if byte == b"\r":
                client.settimeout(0.5)
                try:
                    peek = client.recv(1)
                    if peek and peek != b"\n":
                        buf += peek
                except socket.timeout:
                    pass
                finally:
                    client.settimeout(30)
            return buf.decode("utf-8", errors="replace")
        if byte == b"\x7f" or byte == b"\x08":  # backspace/delete
            if buf:
                buf = buf[:-1]
                if echo:
                    client.sendall(b"\x08 \x08")
            continue
        buf += byte
        if echo:
            client.sendall(byte)


def handle_telnet(client, addr, service_name, port):
    """Fake Telnet server - captures login attempts with interactive prompts."""
    client.settimeout(30)
    # Send telnet negotiation (suppress go-ahead, echo) then banner
    client.sendall(
        b"\xff\xfb\x01"  # WILL ECHO
        b"\xff\xfb\x03"  # WILL SUPPRESS-GO-AHEAD
        b"\xff\xfd\x18"  # DO TERMINAL-TYPE
        b"\xff\xfd\x1f"  # DO NAWS
    )
    client.sendall(TELNET_BANNER)

    # Allow up to 3 login attempts
    for attempt in range(3):
        try:
            client.sendall(b"login: ")
            username = _telnet_read_line(client, echo=True)
            if username is None:
                break

            client.sendall(b"Password: ")
            password = _telnet_read_line(client, echo=False)
            client.sendall(b"\r\n")
            if password is None:
                break

            log_connection(addr[0], addr[1], service_name, port,
                           username=username, password=password,
                           details=f"Login attempt #{attempt + 1}")

            time.sleep(1.5)
            client.sendall(b"\r\nLogin incorrect\r\n")
        except socket.timeout:
            log_connection(addr[0], addr[1], service_name, port,
                           details=f"Telnet timeout at attempt #{attempt + 1}")
            break
        except (ConnectionResetError, BrokenPipeError, OSError):
            break


def handle_http(client, addr, service_name, port):
    """Fake HTTP server with credential capture form."""
    client.settimeout(15)
    try:
        data = client.recv(8192)
        request = data.decode("utf-8", errors="replace")
        first_line = request.split("\r\n")[0] if request else ""

        if request.startswith("POST"):
            username, password = _parse_http_post(data)
            log_connection(addr[0], addr[1], service_name, port,
                           username=username, password=password,
                           details=f"POST credentials: {first_line}")
            client.sendall(FAKE_LOGIN_FAIL_HTML)
        else:
            log_connection(addr[0], addr[1], service_name, port,
                           details=first_line[:200])
            client.sendall(FAKE_LOGIN_HTML)
    except socket.timeout:
        log_connection(addr[0], addr[1], service_name, port,
                       details="Connection (no data)")


def handle_https(client, addr, service_name, port):
    """Fake HTTPS server wrapping the HTTP credential capture."""
    _ensure_self_signed_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    try:
        tls_client = ctx.wrap_socket(client, server_side=True)
        handle_http(tls_client, addr, service_name, port)
        tls_client.close()
    except ssl.SSLError as e:
        log_connection(addr[0], addr[1], service_name, port,
                       details=f"SSL handshake failed: {e}")
    except Exception as e:
        log_connection(addr[0], addr[1], service_name, port,
                       details=f"HTTPS error: {e}")


def handle_rdp(client, addr, service_name, port):
    """Fake RDP service on port 8443 - logs connection attempts."""
    client.settimeout(15)
    try:
        data = client.recv(4096)
        hex_data = data.hex()[:200] if data else "empty"
        log_connection(addr[0], addr[1], service_name, port,
                       details=f"RDP data (hex): {hex_data}")
        # Send a minimal RDP negotiation failure to keep scanners interested
        client.sendall(b"\x03\x00\x00\x09\x02\xf0\x80\x21\x80")
    except socket.timeout:
        log_connection(addr[0], addr[1], service_name, port,
                       details="RDP connection (no data)")


def handle_smtp(client, addr, service_name, port):
    """Fake SMTP server - captures EHLO, MAIL FROM, AUTH attempts."""
    client.settimeout(30)
    client.sendall(SMTP_BANNER)
    conversation = []

    for _ in range(20):
        try:
            data = client.recv(1024)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            conversation.append(line)
            upper = line.upper()

            if upper.startswith("EHLO") or upper.startswith("HELO"):
                client.sendall(
                    b"250-mail.example.com\r\n"
                    b"250-AUTH LOGIN PLAIN\r\n"
                    b"250-STARTTLS\r\n"
                    b"250 OK\r\n"
                )
            elif upper.startswith("AUTH"):
                log_connection(addr[0], addr[1], service_name, port,
                               details=f"AUTH attempt: {line}")
                client.sendall(b"535 5.7.8 Authentication failed\r\n")
            elif upper.startswith("MAIL FROM"):
                client.sendall(b"250 OK\r\n")
            elif upper.startswith("RCPT TO"):
                client.sendall(b"250 OK\r\n")
            elif upper.startswith("DATA"):
                client.sendall(b"354 Start mail input\r\n")
            elif upper.startswith("QUIT"):
                client.sendall(b"221 Bye\r\n")
                break
            elif upper.startswith("STARTTLS"):
                client.sendall(b"454 TLS not available\r\n")
            else:
                client.sendall(b"502 Command not recognized\r\n")
        except socket.timeout:
            break

    if conversation:
        log_connection(addr[0], addr[1], service_name, port,
                       details="SMTP session: " + " | ".join(conversation)[:1000])


def handle_mssql(client, addr, service_name, port):
    """Fake MSSQL server (ports 1433/1434)."""
    client.settimeout(15)
    try:
        data = client.recv(4096)
        if data:
            hex_data = data.hex()[:200]
            log_connection(addr[0], addr[1], service_name, port,
                           details=f"MSSQL data: {hex_data}")
            client.sendall(MSSQL_PRELOGIN_RESPONSE)
            # Try to receive login packet
            data = client.recv(4096)
            if data:
                log_connection(addr[0], addr[1], service_name, port,
                               details=f"MSSQL login packet: {data.hex()[:300]}")
        else:
            log_connection(addr[0], addr[1], service_name, port,
                           details="Connection (no data)")
    except socket.timeout:
        log_connection(addr[0], addr[1], service_name, port,
                       details="MSSQL connection timeout")


def handle_mysql(client, addr, service_name, port):
    """Fake MySQL server (port 3306)."""
    client.settimeout(15)
    client.sendall(MYSQL_GREETING)
    try:
        data = client.recv(4096)
        if data and len(data) > 36:
            # Try to extract username from MySQL handshake response
            try:
                username = data[36:].split(b"\x00")[0].decode("utf-8", errors="replace")
            except Exception:
                username = None
            log_connection(addr[0], addr[1], service_name, port,
                           username=username,
                           details=f"MySQL auth: {data.hex()[:200]}")
            # Send access denied
            err = (b"\x17\x00\x00\x02\xff\x15\x04"
                   b"#28000Access denied for user")
            client.sendall(err)
        else:
            log_connection(addr[0], addr[1], service_name, port,
                           details="MySQL connection (no auth data)")
    except socket.timeout:
        log_connection(addr[0], addr[1], service_name, port,
                       details="MySQL connection timeout")


# ---------------------------------------------------------------------------
# Service registry and startup
# ---------------------------------------------------------------------------

SERVICE_DEFINITIONS = [
    (80, "HTTP", handle_http),
    (443, "HTTPS", handle_https),
    (22, "SSH", handle_ssh),
    (23, "Telnet", handle_telnet),
    (8443, "RDP", handle_rdp),
    (25, "SMTP", handle_smtp),
    (1433, "MSSQL", handle_mssql),
    (1434, "MSSQL-Browser", handle_mssql),
    (3306, "MySQL", handle_mysql),
]


def start_all_services():
    """Start all honeypot services and return the list of threads."""
    _ensure_self_signed_cert()
    _ensure_ssh_host_key()
    services = []
    for port, name, handler in SERVICE_DEFINITIONS:
        svc = HoneypotService(port, name, handler)
        svc.start()
        services.append(svc)
    return services


def stop_all_services(services):
    """Stop all honeypot services."""
    for svc in services:
        svc.stop()
    for svc in services:
        svc.join(timeout=3)
