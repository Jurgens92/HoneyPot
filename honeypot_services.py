"""Fake honeypot services that listen on various ports and log connection attempts."""

import socket
import ssl
import struct
import threading
import logging
import os
import time

import paramiko

from database import log_connection, close_db

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

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Corp"),
        x509.NameAttribute(NameOID.COMMON_NAME, "portal.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )

    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logger.info("Generated self-signed certificate for HTTPS honeypot")


def _parse_http_post(data):
    """Extract username and password from an HTTP POST body."""
    try:
        from urllib.parse import unquote_plus
        body = data.split(b"\r\n\r\n", 1)[-1].decode("utf-8", errors="replace")
        params = {}
        for pair in body.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k] = unquote_plus(v).strip()
        return params.get("username"), params.get("password")
    except Exception:
        return None, None


# ---------------------------------------------------------------------------
# NTLMSSP / CredSSP helpers for RDP NLA credential capture
# ---------------------------------------------------------------------------

_NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
_NTLMSSP_TYPE_NEGOTIATE = 1
_NTLMSSP_TYPE_CHALLENGE = 2
_NTLMSSP_TYPE_AUTHENTICATE = 3

# Challenge negotiate flags
_NTLM_CHALLENGE_FLAGS = (
    0x00000001   # UNICODE
    | 0x00000004   # REQUEST_TARGET
    | 0x00000200   # NTLM
    | 0x00008000   # ALWAYS_SIGN
    | 0x00020000   # TARGET_TYPE_SERVER
    | 0x00080000   # EXTENDED_SESSIONSECURITY
    | 0x00800000   # TARGET_INFO
    | 0x02000000   # VERSION
    | 0x20000000   # 128-BIT
    | 0x40000000   # KEY_EXCH
    | 0x80000000   # 56-BIT
)

# NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
_NTLMSSP_OID_BYTES = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"


def _der_length_encode(length):
    """Encode a length in DER format."""
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    if length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


def _der_tlv(tag, value):
    """Build a DER TLV (tag-length-value) element."""
    tag_bytes = bytes([tag]) if isinstance(tag, int) else tag
    return tag_bytes + _der_length_encode(len(value)) + value


def _build_ntlmssp_challenge(server_challenge):
    """Build an NTLMSSP Type 2 (Challenge) message with target info."""
    target_name = "SERVER".encode("utf-16-le")

    # TargetInfo AV_PAIRs
    av_pairs = b""
    for av_id, av_val in [
        (0x0002, "WORKGROUP".encode("utf-16-le")),           # MsvAvNbDomainName
        (0x0001, "SERVER".encode("utf-16-le")),              # MsvAvNbComputerName
        (0x0004, "workgroup.local".encode("utf-16-le")),     # MsvAvDnsDomainName
        (0x0003, "server.workgroup.local".encode("utf-16-le")),  # MsvAvDnsComputerName
        (0x0007, struct.pack("<Q", 132700000000000000)),     # MsvAvTimestamp
    ]:
        av_pairs += struct.pack("<HH", av_id, len(av_val)) + av_val
    av_pairs += struct.pack("<HH", 0x0000, 0)  # MsvAvEOL

    # Version: Windows 10.0.19041, NTLMSSP revision 15
    version = struct.pack("<BBHBBBB", 10, 0, 19041, 0, 0, 0, 15)

    # Fixed header is 56 bytes
    fixed_len = 56
    target_name_offset = fixed_len
    target_info_offset = fixed_len + len(target_name)

    msg = _NTLMSSP_SIGNATURE
    msg += struct.pack("<I", _NTLMSSP_TYPE_CHALLENGE)
    msg += struct.pack("<HHI", len(target_name), len(target_name), target_name_offset)
    msg += struct.pack("<I", _NTLM_CHALLENGE_FLAGS)
    msg += server_challenge
    msg += b"\x00" * 8  # Reserved
    msg += struct.pack("<HHI", len(av_pairs), len(av_pairs), target_info_offset)
    msg += version
    msg += target_name
    msg += av_pairs
    return msg


def _wrap_spnego_challenge(ntlmssp_challenge):
    """Wrap an NTLMSSP challenge in a SPNEGO negTokenResp."""
    neg_state = _der_tlv(0xA0, _der_tlv(0x0A, b"\x01"))          # accept-incomplete
    supported_mech = _der_tlv(0xA1, _der_tlv(0x06, _NTLMSSP_OID_BYTES))
    response_token = _der_tlv(0xA2, _der_tlv(0x04, ntlmssp_challenge))
    neg_token_resp = _der_tlv(0x30, neg_state + supported_mech + response_token)
    return _der_tlv(0xA1, neg_token_resp)  # context tag [1] for CHOICE


def _wrap_ts_request(spnego_token):
    """Wrap a SPNEGO token in a CredSSP TSRequest (version 3)."""
    version = _der_tlv(0xA0, _der_tlv(0x02, b"\x03"))
    nego_token = _der_tlv(0xA0, _der_tlv(0x04, spnego_token))
    nego_data = _der_tlv(0x30, nego_token)
    nego_tokens = _der_tlv(0xA1, _der_tlv(0x30, nego_data))
    return _der_tlv(0x30, version + nego_tokens)


def _extract_ntlmssp_from_data(data):
    """Find NTLMSSP message inside raw bytes (skipping ASN.1 wrapping)."""
    idx = data.find(_NTLMSSP_SIGNATURE)
    return data[idx:] if idx >= 0 else None


def _parse_ntlmssp_authenticate(ntlmssp_data):
    """Parse NTLMSSP Type 3 (Authenticate) to extract credentials."""
    if len(ntlmssp_data) < 72:
        return None
    if ntlmssp_data[:8] != _NTLMSSP_SIGNATURE:
        return None
    msg_type = struct.unpack("<I", ntlmssp_data[8:12])[0]
    if msg_type != _NTLMSSP_TYPE_AUTHENTICATE:
        return None

    def _field(offset):
        length = struct.unpack("<H", ntlmssp_data[offset:offset + 2])[0]
        buf_off = struct.unpack("<I", ntlmssp_data[offset + 4:offset + 8])[0]
        return length, buf_off

    result = {}
    try:
        nt_len, nt_off = _field(20)
        dom_len, dom_off = _field(28)
        usr_len, usr_off = _field(36)
        ws_len, ws_off = _field(44)

        if dom_len and dom_off + dom_len <= len(ntlmssp_data):
            result["domain"] = ntlmssp_data[dom_off:dom_off + dom_len].decode("utf-16-le", errors="replace")
        if usr_len and usr_off + usr_len <= len(ntlmssp_data):
            result["username"] = ntlmssp_data[usr_off:usr_off + usr_len].decode("utf-16-le", errors="replace")
        if ws_len and ws_off + ws_len <= len(ntlmssp_data):
            result["workstation"] = ntlmssp_data[ws_off:ws_off + ws_len].decode("utf-16-le", errors="replace")
        if nt_len and nt_off + nt_len <= len(ntlmssp_data):
            result["ntlmv2_hash"] = ntlmssp_data[nt_off:nt_off + nt_len].hex()
    except Exception:
        pass
    return result if result else None


def _rdp_credssp_exchange(tls_client, addr, service_name, port, username_from_cookie):
    """Perform CredSSP/NTLMSSP exchange over TLS to capture RDP credentials."""
    # Receive TSRequest with NTLMSSP_NEGOTIATE
    try:
        data = tls_client.recv(4096)
        if not data:
            return
    except socket.timeout:
        return

    ntlmssp_neg = _extract_ntlmssp_from_data(data)
    if not ntlmssp_neg:
        log_connection(addr[0], addr[1], service_name, port,
                       username=username_from_cookie,
                       details=f"RDP CredSSP non-NTLMSSP ({len(data)} bytes): {data.hex()[:200]}")
        return

    # Send NTLMSSP_CHALLENGE
    server_challenge = os.urandom(8)
    challenge_msg = _build_ntlmssp_challenge(server_challenge)
    spnego_resp = _wrap_spnego_challenge(challenge_msg)
    ts_request = _wrap_ts_request(spnego_resp)

    try:
        tls_client.sendall(ts_request)
    except (ssl.SSLError, OSError):
        return

    # Receive TSRequest with NTLMSSP_AUTHENTICATE
    try:
        data = tls_client.recv(8192)
        if not data:
            return
    except socket.timeout:
        return

    ntlmssp_auth = _extract_ntlmssp_from_data(data)
    if not ntlmssp_auth:
        log_connection(addr[0], addr[1], service_name, port,
                       username=username_from_cookie,
                       details=f"RDP CredSSP auth ({len(data)} bytes): {data.hex()[:200]}")
        return

    creds = _parse_ntlmssp_authenticate(ntlmssp_auth)
    if creds:
        username = creds.get("username", username_from_cookie)
        domain = creds.get("domain", "")
        workstation = creds.get("workstation", "")
        ntlmv2_hash = creds.get("ntlmv2_hash", "")

        details = f"RDP NLA credentials: domain={domain}, workstation={workstation}"
        if ntlmv2_hash:
            details += f", NTLMv2={ntlmv2_hash[:64]}..."

        log_connection(addr[0], addr[1], service_name, port,
                       username=username,
                       password=f"[NTLMv2:{server_challenge.hex()}:{ntlmv2_hash[:64] if ntlmv2_hash else ''}]",
                       details=details)
    else:
        log_connection(addr[0], addr[1], service_name, port,
                       username=username_from_cookie,
                       details=f"RDP NLA auth (unparseable): {data.hex()[:200]}")

    # Send TSRequest with error to cleanly terminate
    err_version = _der_tlv(0xA0, _der_tlv(0x02, b"\x03"))
    err_code = _der_tlv(0xA4, _der_tlv(0x02, b"\x00\x00\x00\x01"))
    try:
        tls_client.sendall(_der_tlv(0x30, err_version + err_code))
    except (ssl.SSLError, OSError):
        pass


# ---------------------------------------------------------------------------
# MSSQL TDS Login7 password decoding
# ---------------------------------------------------------------------------

def _decode_mssql_password(encoded_bytes):
    """Decode an obfuscated MSSQL Login7 password (nibble-swap + XOR 0xA5)."""
    decoded = bytearray()
    for b in encoded_bytes:
        x = b ^ 0xA5
        decoded.append(((x & 0x0F) << 4) | ((x & 0xF0) >> 4))
    return bytes(decoded).decode("utf-16-le", errors="replace")


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

_cached_ssh_host_key = None
_ssh_key_lock = threading.Lock()


def _ensure_ssh_host_key():
    """Generate an RSA host key for the fake SSH server if it doesn't exist.
    Caches the key in memory to avoid re-reading from disk on every connection."""
    global _cached_ssh_host_key
    if _cached_ssh_host_key is not None:
        return _cached_ssh_host_key

    with _ssh_key_lock:
        if _cached_ssh_host_key is not None:
            return _cached_ssh_host_key
        os.makedirs(os.path.dirname(SSH_HOST_KEY_FILE), exist_ok=True)
        if os.path.exists(SSH_HOST_KEY_FILE):
            _cached_ssh_host_key = paramiko.RSAKey(filename=SSH_HOST_KEY_FILE)
        else:
            _cached_ssh_host_key = paramiko.RSAKey.generate(2048)
            _cached_ssh_host_key.write_private_key_file(SSH_HOST_KEY_FILE)
            logger.info("Generated SSH host key for honeypot")
        return _cached_ssh_host_key


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


def _telnet_read_line(client, echo=True, max_length=4096):
    """Read a line from a telnet client, byte by byte, with optional echo."""
    buf = b""
    while len(buf) < max_length:
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
    """Fake RDP service - handles X.224 negotiation and CredSSP/NLA auth capture."""
    client.settimeout(15)
    try:
        # Step 1: Receive X.224 Connection Request
        data = client.recv(4096)
        if not data or len(data) < 11:
            log_connection(addr[0], addr[1], service_name, port,
                           details=f"RDP connection (insufficient data): "
                                   f"{data.hex()[:100] if data else 'empty'}")
            return

        # Validate TPKT header (0x03) and X.224 CR PDU type (0xe0)
        if data[0] != 0x03 or data[5] != 0xe0:
            log_connection(addr[0], addr[1], service_name, port,
                           details=f"RDP non-standard data: {data.hex()[:200]}")
            return

        # Extract cookie/username from "Cookie: mstshash=<user>\r\n"
        username = None
        try:
            decoded = data[11:].decode("ascii", errors="replace")
            if "mstshash=" in decoded:
                username = decoded.split("mstshash=")[1].split("\r")[0].strip()
        except Exception:
            pass

        # Detect requested security protocol from RDP Negotiation Request
        # (type=0x01 flags length=0x0008 requestedProtocols)
        requested_protocol = 0
        neg_offset = data.find(b"\x01\x00\x08\x00")
        if neg_offset >= 0 and neg_offset + 8 <= len(data):
            requested_protocol = int.from_bytes(
                data[neg_offset + 4:neg_offset + 8], "little")

        details = "RDP Connection Request"
        if username:
            details += f" (cookie user: {username})"
        proto_names = []
        if requested_protocol & 0x01:
            proto_names.append("TLS")
        if requested_protocol & 0x02:
            proto_names.append("CredSSP/NLA")
        if requested_protocol & 0x08:
            proto_names.append("RDSTLS")
        if proto_names:
            details += f" protocols=[{','.join(proto_names)}]"

        log_connection(addr[0], addr[1], service_name, port,
                       username=username, details=details)

        # Step 2: Send X.224 Connection Confirm with selected protocol
        if requested_protocol & 0x02:
            # Client supports CredSSP/NLA - agree to PROTOCOL_HYBRID
            selected = b"\x02\x00\x00\x00"
        elif requested_protocol & 0x01:
            # Client supports TLS only
            selected = b"\x01\x00\x00\x00"
        else:
            # Fallback to standard RDP security
            selected = b"\x00\x00\x00\x00"

        cc_response = (
            b"\x03\x00"          # TPKT version 3
            b"\x00\x13"          # TPKT length = 19
            b"\x0e"              # X.224 length = 14
            b"\xd0"              # X.224 CC (Connection Confirm)
            b"\x00\x00"          # dst-ref
            b"\x00\x00"          # src-ref
            b"\x00"              # class options
            b"\x02"              # TYPE_RDP_NEG_RSP
            b"\x00"              # flags
            b"\x08\x00"          # length = 8
            + selected
        )
        client.sendall(cc_response)

        # Step 3: TLS upgrade + protocol-specific handling
        if requested_protocol & 0x02:
            # CredSSP/NLA: upgrade to TLS then perform NTLMSSP exchange
            _ensure_self_signed_cert()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(CERT_FILE, KEY_FILE)
            try:
                tls_client = ctx.wrap_socket(client, server_side=True)
                _rdp_credssp_exchange(tls_client, addr, service_name, port, username)
                tls_client.close()
                return
            except ssl.SSLError as e:
                log_connection(addr[0], addr[1], service_name, port,
                               details=f"RDP TLS handshake failed: {e}")
        elif requested_protocol & 0x01:
            # TLS only (no CredSSP)
            _ensure_self_signed_cert()
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(CERT_FILE, KEY_FILE)
            try:
                tls_client = ctx.wrap_socket(client, server_side=True)
                try:
                    tls_data = tls_client.recv(4096)
                    if tls_data:
                        log_connection(
                            addr[0], addr[1], service_name, port,
                            username=username,
                            details=f"RDP TLS data ({len(tls_data)} bytes): "
                                    f"{tls_data.hex()[:200]}")
                except socket.timeout:
                    pass
                tls_client.close()
                return
            except ssl.SSLError as e:
                log_connection(addr[0], addr[1], service_name, port,
                               details=f"RDP TLS handshake failed: {e}")
        else:
            # Standard RDP security - receive MCS Connect Initial
            try:
                mcs_data = client.recv(4096)
                if mcs_data:
                    log_connection(
                        addr[0], addr[1], service_name, port,
                        details=f"RDP MCS data ({len(mcs_data)} bytes): "
                                f"{mcs_data.hex()[:200]}")
            except socket.timeout:
                pass

    except socket.timeout:
        log_connection(addr[0], addr[1], service_name, port,
                       details="RDP connection timeout")
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        log_connection(addr[0], addr[1], service_name, port,
                       details=f"RDP connection error: {e}")


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
    """Fake MSSQL server (ports 1433/1434) - parses TDS Login7 for credentials."""
    client.settimeout(15)
    try:
        data = client.recv(4096)
        if data:
            log_connection(addr[0], addr[1], service_name, port,
                           details=f"MSSQL prelogin: {data.hex()[:200]}")
            client.sendall(MSSQL_PRELOGIN_RESPONSE)
            # Receive Login7 packet
            data = client.recv(4096)
            if data and len(data) > 8:
                tds_type = data[0]
                if tds_type == 0x10 and len(data) > 56:  # TDS7 LOGIN
                    login_data = data[8:]  # skip 8-byte TDS header
                    try:
                        user_offset = struct.unpack("<H", login_data[40:42])[0]
                        user_length = struct.unpack("<H", login_data[42:44])[0]
                        pwd_offset = struct.unpack("<H", login_data[44:46])[0]
                        pwd_length = struct.unpack("<H", login_data[46:48])[0]

                        username = None
                        password = None

                        if user_length > 0:
                            u_end = user_offset + user_length * 2
                            if u_end <= len(login_data):
                                username = login_data[user_offset:u_end].decode(
                                    "utf-16-le", errors="replace")

                        if pwd_length > 0:
                            p_end = pwd_offset + pwd_length * 2
                            if p_end <= len(login_data):
                                password = _decode_mssql_password(
                                    login_data[pwd_offset:p_end])

                        log_connection(addr[0], addr[1], service_name, port,
                                       username=username, password=password,
                                       details="MSSQL Login7 auth")
                    except Exception as e:
                        log_connection(addr[0], addr[1], service_name, port,
                                       details=f"MSSQL Login7 parse error: {e}, "
                                               f"data: {data.hex()[:300]}")
                else:
                    log_connection(addr[0], addr[1], service_name, port,
                                   details=f"MSSQL packet type=0x{tds_type:02x}: "
                                           f"{data.hex()[:300]}")

                # Send TDS error response (login failed)
                err_msg = "Login failed".encode("utf-16-le")
                srv_name = "SQL".encode("utf-16-le")
                # Build ERROR token (0xAA)
                err_token = struct.pack("<BHIBB",
                                        0xAA,                    # ERROR token
                                        6 + len(err_msg) + 2 + len(srv_name) + 2 + 2,
                                        18456,                   # error number
                                        1, 14)                   # state, severity
                err_token += struct.pack("<H", len(err_msg) // 2) + err_msg
                err_token += struct.pack("<H", len(srv_name) // 2) + srv_name
                err_token += struct.pack("<H", 0)  # procedure name (empty)
                err_token += struct.pack("<I", 0)  # line number
                # Wrap in TDS RESPONSE header
                tds_len = 8 + len(err_token)
                tds_header = struct.pack(">BBHBBBB",
                                         0x04,     # TDS RESPONSE
                                         0x01,     # STATUS: EOM
                                         tds_len,
                                         0, 0,     # SPID
                                         1, 0)     # PacketID, Window
                try:
                    client.sendall(tds_header + err_token)
                except (BrokenPipeError, OSError):
                    pass
            elif data:
                log_connection(addr[0], addr[1], service_name, port,
                               details=f"MSSQL short packet: {data.hex()[:200]}")
        else:
            log_connection(addr[0], addr[1], service_name, port,
                           details="Connection (no data)")
    except socket.timeout:
        log_connection(addr[0], addr[1], service_name, port,
                       details="MSSQL connection timeout")


def handle_mysql(client, addr, service_name, port):
    """Fake MySQL server (port 3306) - captures username and password hash."""
    client.settimeout(15)
    client.sendall(MYSQL_GREETING)
    try:
        data = client.recv(4096)
        if data and len(data) > 36:
            username = None
            auth_hash = None
            try:
                # MySQL packet: 3-byte length + 1-byte seq + payload
                # HandshakeResponse41 payload starts at byte 4:
                #   cap_flags(4) + max_packet(4) + charset(1) + reserved(23) = 32
                # Username starts at payload offset 32 → byte 36 of packet
                cap_flags = struct.unpack("<I", data[4:8])[0]
                payload_after_fixed = data[36:]
                null_pos = payload_after_fixed.find(b"\x00")
                if null_pos >= 0:
                    username = payload_after_fixed[:null_pos].decode(
                        "utf-8", errors="replace")
                    auth_data = payload_after_fixed[null_pos + 1:]
                    if auth_data:
                        if cap_flags & 0x00200000:  # CLIENT_PLUGIN_AUTH_LENENC
                            hash_len = auth_data[0]
                            if hash_len < 0xFB and len(auth_data) > hash_len:
                                auth_hash = auth_data[1:1 + hash_len].hex()
                        elif cap_flags & 0x00008000:  # CLIENT_SECURE_CONNECTION
                            hash_len = auth_data[0]
                            if len(auth_data) > hash_len:
                                auth_hash = auth_data[1:1 + hash_len].hex()
                        else:
                            # Null-terminated auth response
                            auth_hash = auth_data.split(b"\x00")[0].hex()
            except Exception:
                # Fallback: try simple username extraction
                try:
                    username = data[36:].split(b"\x00")[0].decode(
                        "utf-8", errors="replace")
                except Exception:
                    pass

            details = "MySQL auth"
            if auth_hash:
                details += f", password_hash={auth_hash}"

            log_connection(addr[0], addr[1], service_name, port,
                           username=username, details=details)
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
    (3389, "RDP", handle_rdp),
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
