#!/usr/bin/env python3
"""Interoperability tests: SYBAU-CORE as a client of real Xray and sing-box.

For every case a reference server (Xray or sing-box) is started on
loopback, `sybau` is started with a mixed inbound and an outbound for the
case, and traffic is pushed through the pair:

  * TCP: small GET, 8 MiB download, 2 MiB upload (checksums compared),
         and a server-speaks-first service;
  * UDP: SOCKS5 UDP ASSOCIATE to two echo servers, several datagram sizes.

Usage: run.py [--filter SUBSTRING] [--list] [--keep-logs]
Reference binaries come from build-refs.sh (tests/interop/.bin) or from
XRAY_BIN / SINGBOX_BIN.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
WORK = os.path.join(HERE, ".work")
XRAY = os.environ.get("XRAY_BIN", os.path.join(HERE, ".bin", "xray"))
SINGBOX = os.environ.get("SINGBOX_BIN", os.path.join(HERE, ".bin", "sing-box"))
SYBAU = os.environ.get("SYBAU_BIN", os.path.join(ROOT, "target", "debug", "sybau"))

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
PASSWORD = "interop-password"
SNI = "sybau.test"
BIG = bytes(range(256)) * 4096 * 8  # 8 MiB
BIG_SHA = hashlib.sha256(BIG).hexdigest()
UPLOAD = os.urandom(2 * 1024 * 1024)
UPLOAD_SHA = hashlib.sha256(UPLOAD).hexdigest()


def b64key(n, fill):
    return base64.b64encode(bytes([fill]) * n).decode()


# --------------------------------------------------------------------------
# Local services the proxied traffic is sent to
# --------------------------------------------------------------------------

class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        body = BIG if self.path == "/big" else b"hello from origin"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        h = hashlib.sha256()
        while n > 0:
            chunk = self.rfile.read(min(n, 65536))
            if not chunk:
                break
            h.update(chunk)
            n -= len(chunk)
        body = h.hexdigest().encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class ThreadedHTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Banner(socketserver.BaseRequestHandler):
    """Speaks first, like SMTP or SSH: the client sends nothing."""

    def handle(self):
        self.request.sendall(b"220 banner ready\r\n")
        try:
            self.request.recv(16)
        except OSError:
            pass


class ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def udp_echo(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))

    def loop():
        while True:
            data, addr = sock.recvfrom(65535)
            sock.sendto(data, addr)

    threading.Thread(target=loop, daemon=True).start()


def free_ports(n):
    socks, ports = [], []
    for _ in range(n):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks.append(s)
        ports.append(s.getsockname()[1])
    for s in socks:
        s.close()
    return ports


def wait_port(port, proc, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


# --------------------------------------------------------------------------
# Certificate for the TLS cases
# --------------------------------------------------------------------------

def make_cert():
    cert, key = os.path.join(WORK, "cert.pem"), os.path.join(WORK, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-keyout", key, "-out", cert, "-days", "30", "-subj", f"/CN={SNI}",
         "-addext", f"subjectAltName=DNS:{SNI}"],
        check=True, capture_output=True)
    der = subprocess.run(["openssl", "x509", "-in", cert, "-outform", "DER"], check=True, capture_output=True).stdout
    return cert, key, hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------
# Case definitions
# --------------------------------------------------------------------------

class Case:
    def __init__(self, name, server, inbound, outbound, udp=True, expect_fail=False):
        self.name = name
        self.server = server          # "xray" | "sing-box"
        self.inbound = inbound        # server inbound (dict, without listen/port)
        self.outbound = outbound      # sybau outbound (dict, without tag/server/port)
        self.udp = udp
        self.expect_fail = expect_fail


def build_cases(cert, key, pin):
    cases = []
    tls_client = {"server_name": SNI, "pinned_cert_sha256": [pin]}
    xtls = {"security": "tls", "tlsSettings": {"certificates": [{"certificateFile": cert, "keyFile": key}]}}
    stls = {"enabled": True, "certificate_path": cert, "key_path": key}

    # ---- Xray: transports, exercised with VLESS -------------------------
    def xray_stream(network=None, tls=False, **settings):
        s = {}
        if network:
            s["network"] = network
        s.update(settings)
        if tls:
            s.update(xtls)
        return s

    transports = [
        ("tcp", {}, None, False),
        ("tcp+tls", {}, None, True),
        ("tcp+http-obfs", {"network": "tcp", "tcpSettings": {"header": {"type": "http", "response": {}}}},
         {"type": "tcp", "http_obfs": {"host": ["www.example.com"], "path": "/"}}, False),
        ("ws", {"network": "ws", "wsSettings": {"path": "/ws"}}, {"type": "ws", "path": "/ws"}, False),
        ("ws+tls", {"network": "ws", "wsSettings": {"path": "/ws"}}, {"type": "ws", "path": "/ws"}, True),
        ("ws+tls+early-data", {"network": "ws", "wsSettings": {"path": "/ws"}},
         {"type": "ws", "path": "/ws", "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}, True),
        ("httpupgrade", {"network": "httpupgrade", "httpupgradeSettings": {"path": "/up"}},
         {"type": "httpupgrade", "path": "/up"}, False),
        ("httpupgrade+tls", {"network": "httpupgrade", "httpupgradeSettings": {"path": "/up"}},
         {"type": "httpupgrade", "path": "/up"}, True),
        ("grpc", {"network": "grpc", "grpcSettings": {"serviceName": "Svc"}},
         {"type": "grpc", "service_name": "Svc"}, False),
        ("grpc+tls", {"network": "grpc", "grpcSettings": {"serviceName": "Svc"}},
         {"type": "grpc", "service_name": "Svc"}, True),
        ("grpc-multi+tls", {"network": "grpc", "grpcSettings": {"serviceName": "Svc", "multiMode": True}},
         {"type": "grpc", "service_name": "Svc", "multi_mode": True}, True),
    ]
    for name, stream, transport, tls in transports:
        ss = dict(stream)
        if tls:
            ss.update(xtls)
        ob = {"type": "vless", "uuid": UUID}
        if transport:
            ob["transport"] = transport
        if tls:
            ob["tls"] = tls_client
        cases.append(Case(
            f"xray/vless/{name}", "xray",
            {"protocol": "vless", "settings": {"clients": [{"id": UUID}], "decryption": "none"}, "streamSettings": ss},
            ob))

    # ---- Xray: VMess securities ----------------------------------------
    for sec in ["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"]:
        cases.append(Case(
            f"xray/vmess/tcp/{sec}", "xray",
            {"protocol": "vmess", "settings": {"clients": [{"id": UUID}]}},
            {"type": "vmess", "uuid": UUID, "security": sec}))
    cases.append(Case(
        "xray/vmess/tcp/no-global-padding", "xray",
        {"protocol": "vmess", "settings": {"clients": [{"id": UUID}]}},
        {"type": "vmess", "uuid": UUID, "security": "aes-128-gcm", "global_padding": False}))
    cases.append(Case(
        "xray/vmess/ws+tls", "xray",
        {"protocol": "vmess", "settings": {"clients": [{"id": UUID}]},
         "streamSettings": {"network": "ws", "wsSettings": {"path": "/vm"}, **xtls}},
        {"type": "vmess", "uuid": UUID, "tls": tls_client, "transport": {"type": "ws", "path": "/vm"}}))
    cases.append(Case(
        "xray/vmess/grpc+tls", "xray",
        {"protocol": "vmess", "settings": {"clients": [{"id": UUID}]},
         "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "Vm"}, **xtls}},
        {"type": "vmess", "uuid": UUID, "tls": tls_client, "transport": {"type": "grpc", "service_name": "Vm"}}))

    # ---- Xray: Trojan ---------------------------------------------------
    cases.append(Case(
        "xray/trojan/tcp+tls", "xray",
        {"protocol": "trojan", "settings": {"clients": [{"password": PASSWORD}]}, "streamSettings": dict(xtls)},
        {"type": "trojan", "password": PASSWORD, "tls": tls_client}))
    cases.append(Case(
        "xray/trojan/ws+tls", "xray",
        {"protocol": "trojan", "settings": {"clients": [{"password": PASSWORD}]},
         "streamSettings": {"network": "ws", "wsSettings": {"path": "/tj"}, **xtls}},
        {"type": "trojan", "password": PASSWORD, "tls": tls_client, "transport": {"type": "ws", "path": "/tj"}}))
    cases.append(Case(
        "xray/trojan/grpc+tls", "xray",
        {"protocol": "trojan", "settings": {"clients": [{"password": PASSWORD}]},
         "streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "Tj"}, **xtls}},
        {"type": "trojan", "password": PASSWORD, "tls": tls_client, "transport": {"type": "grpc", "service_name": "Tj"}}))

    # ---- Xray: Shadowsocks ---------------------------------------------
    for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"]:
        cases.append(Case(
            f"xray/shadowsocks/{method}", "xray",
            {"protocol": "shadowsocks", "settings": {"method": method, "password": PASSWORD, "network": "tcp,udp"}},
            {"type": "shadowsocks", "method": method, "password": PASSWORD}))
    for method, klen in [("2022-blake3-aes-128-gcm", 16), ("2022-blake3-aes-256-gcm", 32),
                         ("2022-blake3-chacha20-poly1305", 32)]:
        cases.append(Case(
            f"xray/shadowsocks/{method}", "xray",
            {"protocol": "shadowsocks",
             "settings": {"method": method, "password": b64key(klen, 1), "network": "tcp,udp"}},
            {"type": "shadowsocks", "method": method, "password": b64key(klen, 1)}))
    for method, klen in [("2022-blake3-aes-128-gcm", 16), ("2022-blake3-aes-256-gcm", 32)]:
        cases.append(Case(
            f"xray/shadowsocks/{method}/multi-user", "xray",
            {"protocol": "shadowsocks",
             "settings": {"method": method, "password": b64key(klen, 1), "network": "tcp,udp",
                          "clients": [{"password": b64key(klen, 2), "email": "u@x"}]}},
            {"type": "shadowsocks", "method": method, "password": b64key(klen, 1) + ":" + b64key(klen, 2)}))

    # ---- sing-box -------------------------------------------------------
    sb_transports = [
        ("tcp", None, None, False),
        ("tcp+tls", None, None, True),
        ("ws+tls", {"type": "ws", "path": "/ws"}, {"type": "ws", "path": "/ws"}, True),
        ("ws+early-data", {"type": "ws", "path": "/ws", "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"},
         {"type": "ws", "path": "/ws", "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"}, False),
        ("ws+early-data-in-path", {"type": "ws", "path": "/ws", "max_early_data": 2048},
         {"type": "ws", "path": "/ws", "max_early_data": 2048}, False),
        ("httpupgrade+tls", {"type": "httpupgrade", "path": "/up"}, {"type": "httpupgrade", "path": "/up"}, True),
        ("grpc+tls", {"type": "grpc", "service_name": "Svc"}, {"type": "grpc", "service_name": "Svc"}, True),
        ("http2+tls", {"type": "http", "path": "/h2"}, {"type": "http", "path": "/h2", "host": [SNI]}, True),
    ]
    for name, st, ct, tls in sb_transports:
        ib = {"type": "vless", "users": [{"uuid": UUID}]}
        ob = {"type": "vless", "uuid": UUID}
        if st:
            ib["transport"] = st
            ob["transport"] = ct
        if tls:
            ib["tls"] = stls
            ob["tls"] = tls_client
        cases.append(Case(f"sing-box/vless/{name}", "sing-box", ib, ob))

    for sec in ["auto", "chacha20-poly1305", "none", "zero"]:
        cases.append(Case(
            f"sing-box/vmess/tcp/{sec}", "sing-box",
            {"type": "vmess", "users": [{"uuid": UUID, "alterId": 0}]},
            {"type": "vmess", "uuid": UUID, "security": sec}))
    cases.append(Case(
        "sing-box/trojan/tcp+tls", "sing-box",
        {"type": "trojan", "users": [{"password": PASSWORD}], "tls": stls},
        {"type": "trojan", "password": PASSWORD, "tls": tls_client}))
    for method in ["aes-128-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "none"]:
        cases.append(Case(
            f"sing-box/shadowsocks/{method}", "sing-box",
            {"type": "shadowsocks", "method": method, "password": PASSWORD},
            {"type": "shadowsocks", "method": method, "password": PASSWORD}))
    for method, klen in [("2022-blake3-aes-128-gcm", 16), ("2022-blake3-aes-256-gcm", 32),
                         ("2022-blake3-chacha20-poly1305", 32)]:
        cases.append(Case(
            f"sing-box/shadowsocks/{method}", "sing-box",
            {"type": "shadowsocks", "method": method, "password": b64key(klen, 3)},
            {"type": "shadowsocks", "method": method, "password": b64key(klen, 3)}))
    cases.append(Case(
        "sing-box/shadowsocks/2022-blake3-aes-128-gcm/multi-user", "sing-box",
        {"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": b64key(16, 3),
         "users": [{"name": "u", "password": b64key(16, 4)}]},
        {"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": b64key(16, 3) + ":" + b64key(16, 4)}))

    # ---- Upstream proxies (sing-box as SOCKS5 / HTTP server) ------------
    users = [{"username": "user", "password": "pass"}]
    cases.append(Case("sing-box/socks5/auth", "sing-box", {"type": "socks", "users": users},
                      {"type": "socks", "username": "user", "password": "pass"}))
    cases.append(Case("sing-box/socks5/no-auth", "sing-box", {"type": "socks"}, {"type": "socks"}))
    cases.append(Case("sing-box/http-connect/auth", "sing-box", {"type": "http", "users": users},
                      {"type": "http", "username": "user", "password": "pass"}, udp=False))
    cases.append(Case("sing-box/http-connect+tls", "sing-box", {"type": "http", "tls": stls},
                      {"type": "http", "tls": tls_client}, udp=False))

    # ---- TLS verification ----------------------------------------------
    trojan_in = {"protocol": "trojan", "settings": {"clients": [{"password": PASSWORD}]}, "streamSettings": dict(xtls)}
    cases.append(Case("tls/insecure-accepts-self-signed", "xray", trojan_in,
                      {"type": "trojan", "password": PASSWORD, "tls": {"server_name": SNI, "insecure": True}}))
    cases.append(Case("tls/wrong-pin-is-rejected", "xray", trojan_in,
                      {"type": "trojan", "password": PASSWORD,
                       "tls": {"server_name": SNI, "pinned_cert_sha256": ["00" * 32]}}, expect_fail=True))
    cases.append(Case("tls/self-signed-without-pin-is-rejected", "xray", trojan_in,
                      {"type": "trojan", "password": PASSWORD, "tls": {"server_name": SNI}}, expect_fail=True))
    cases.append(Case("auth/wrong-uuid-is-rejected", "xray",
                      {"protocol": "vless", "settings": {"clients": [{"id": UUID}], "decryption": "none"}},
                      {"type": "vless", "uuid": "00000000-0000-4000-8000-000000000000"}, expect_fail=True))
    return cases


# --------------------------------------------------------------------------
# Traffic checks
# --------------------------------------------------------------------------

def curl(proxy_port, url, extra=(), timeout=30):
    cmd = ["curl", "-sS", "--noproxy", "", "-m", str(timeout), "-x", f"socks5h://127.0.0.1:{proxy_port}", *extra, url]
    return subprocess.run(cmd, capture_output=True)


def check_tcp(proxy_port, origin_port, banner_port):
    r = curl(proxy_port, f"http://127.0.0.1:{origin_port}/small", timeout=10)
    if r.stdout != b"hello from origin":
        return f"small GET: {r.stderr.decode().strip() or r.stdout[:80]!r}"
    r = curl(proxy_port, f"http://127.0.0.1:{origin_port}/big")
    if hashlib.sha256(r.stdout).hexdigest() != BIG_SHA:
        return f"8 MiB download: got {len(r.stdout)} bytes, {r.stderr.decode().strip()}"
    r = curl(proxy_port, f"http://127.0.0.1:{origin_port}/echo",
             ["-X", "POST", "-H", "Expect:", "--data-binary", "@" + os.path.join(WORK, "upload.bin")])
    if r.stdout.decode() != UPLOAD_SHA:
        return f"2 MiB upload: {r.stderr.decode().strip() or r.stdout[:80]!r}"
    # Server speaks first: nothing is written by the client.
    try:
        s = socks5_tcp(proxy_port, "127.0.0.1", banner_port)
        s.settimeout(5)
        got = s.recv(64)
        s.close()
        if got != b"220 banner ready\r\n":
            return f"server-first: got {got!r}"
    except OSError as e:
        return f"server-first: {e}"
    return None


def socks5_tcp(proxy_port, host, port):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise OSError("socks5 method")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", port))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise OSError("socks5 connect")
    return s


def check_udp(proxy_port, echo_ports):
    ctrl = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    try:
        ctrl.sendall(b"\x05\x01\x00")
        if ctrl.recv(2) != b"\x05\x00":
            return "udp: method negotiation"
        ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        rep = ctrl.recv(10)
        if len(rep) != 10 or rep[1] != 0:
            return f"udp: associate refused {rep!r}"
        relay = (socket.inet_ntoa(rep[4:8]), struct.unpack(">H", rep[8:10])[0])
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(5)
        for size in (1, 100, 1200):
            for port in echo_ports:
                payload = os.urandom(size)
                head = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", port)
                u.sendto(head + payload, relay)
                try:
                    data, _ = u.recvfrom(65535)
                except socket.timeout:
                    return f"udp: no reply for {size}-byte datagram to port {port}"
                if data[:4] != b"\x00\x00\x00\x01" or data[10:] != payload:
                    return f"udp: wrong reply for {size}-byte datagram"
                if struct.unpack(">H", data[8:10])[0] != port:
                    return f"udp: reply attributed to port {struct.unpack('>H', data[8:10])[0]}, expected {port}"
        u.close()
        return None
    finally:
        ctrl.close()


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def server_command(case, port, path):
    if case.server == "xray":
        cfg = {"log": {"loglevel": "warning"},
               "inbounds": [{"listen": "127.0.0.1", "port": port, **case.inbound}],
               "outbounds": [{"protocol": "freedom"}]}
        cmd = [XRAY, "run", "-c", path]
    else:
        cfg = {"log": {"level": "warn"},
               "inbounds": [{"listen": "127.0.0.1", "listen_port": port, **case.inbound}],
               "outbounds": [{"type": "direct"}]}
        cmd = [SINGBOX, "run", "-c", path]
    with open(path, "w") as f:
        json.dump(cfg, f, indent=1)
    return cmd


def run_case(case, index, services, keep_logs):
    origin_port, banner_port, echo_ports = services
    server_port, proxy_port = free_ports(2)
    slug = case.name.replace("/", "_").replace("+", "-")
    server_cfg = os.path.join(WORK, f"{slug}.server.json")
    client_cfg = os.path.join(WORK, f"{slug}.sybau.json")
    server_log = open(os.path.join(WORK, f"{slug}.server.log"), "w")
    client_log = open(os.path.join(WORK, f"{slug}.sybau.log"), "w")
    with open(client_cfg, "w") as f:
        json.dump({
            "log": {"level": "debug"},
            "control": {"enabled": False},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "port": proxy_port}],
            "outbounds": [{"tag": "proxy", "server": "127.0.0.1", "port": server_port, **case.outbound}],
        }, f, indent=1)

    server = subprocess.Popen(server_command(case, server_port, server_cfg), stdout=server_log, stderr=subprocess.STDOUT)
    client = subprocess.Popen([SYBAU, "run", "-c", client_cfg, "--profile", f"interop-{index}"],
                              stdout=client_log, stderr=subprocess.STDOUT)
    error = None
    try:
        # Shadowsocks UDP-only and QUIC servers have no TCP port to probe,
        # but every server here listens on TCP as well.
        if not wait_port(server_port, server):
            error = "reference server did not start"
        elif not wait_port(proxy_port, client):
            error = "sybau did not start"
        else:
            error = check_tcp(proxy_port, origin_port, banner_port)
            if error is None and case.udp and not case.expect_fail:
                error = check_udp(proxy_port, echo_ports)
    finally:
        for p in (client, server):
            p.terminate()
        for p in (client, server):
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        server_log.close()
        client_log.close()

    if case.expect_fail:
        ok = error is not None and "did not start" not in error
        detail = "" if ok else (error or "traffic passed although it must not")
    else:
        ok, detail = error is None, error or ""
    if ok and not keep_logs:
        for path in (server_cfg, client_cfg, server_log.name, client_log.name):
            os.remove(path)
    return ok, detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", default="")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--keep-logs", action="store_true")
    ap.add_argument("--report", help="write a Markdown table of results to this file")
    args = ap.parse_args()

    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    cert, key, pin = make_cert()
    cases = [c for c in build_cases(cert, key, pin) if args.filter in c.name]
    if args.list:
        print("\n".join(c.name for c in cases))
        return 0
    for binary in (XRAY, SINGBOX, SYBAU):
        if not os.path.exists(binary):
            print(f"missing {binary} (run tests/interop/build-refs.sh and `cargo build -p sybau`)", file=sys.stderr)
            return 2
    with open(os.path.join(WORK, "upload.bin"), "wb") as f:
        f.write(UPLOAD)

    origin_port, banner_port, echo1, echo2 = free_ports(4)
    threading.Thread(target=ThreadedHTTP(("127.0.0.1", origin_port), Origin).serve_forever, daemon=True).start()
    threading.Thread(target=ThreadedTCP(("127.0.0.1", banner_port), Banner).serve_forever, daemon=True).start()
    udp_echo(echo1)
    udp_echo(echo2)
    services = (origin_port, banner_port, (echo1, echo2))

    results = []
    for i, case in enumerate(cases):
        started = time.time()
        ok, detail = run_case(case, i, services, args.keep_logs)
        results.append((case, ok, detail))
        mark = "ok  " if ok else "FAIL"
        print(f"{mark} {case.name:58s} {time.time() - started:5.1f}s  {detail}", flush=True)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} cases passed")
    if args.report:
        with open(args.report, "w") as f:
            f.write("| Case | TCP | UDP |\n|---|---|---|\n")
            for case, ok, _ in results:
                tcp = "rejected, as it must be" if case.expect_fail and ok else ("pass" if ok else "FAIL")
                udp = "—" if (not case.udp or case.expect_fail) else ("pass" if ok else "FAIL")
                f.write(f"| `{case.name}` | {tcp} | {udp} |\n")
    if failed:
        print(f"logs of failed cases are in {WORK}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
