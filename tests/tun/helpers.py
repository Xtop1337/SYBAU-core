"""Small servers and clients for the TUN end-to-end test (stdlib only).

  helpers.py http-server ADDR...        HTTP on ADDR:8080, body = client IP
  helpers.py udp-echo ADDR              UDP echo on ADDR:9000, prefixed with client IP
  helpers.py udp-ask HOST PORT          send a datagram, print the reply
  helpers.py dns-ask SERVER NAME [tcp]  A query, print the answers
  helpers.py fetch URL                  GET, print sha256 and size of the body
  helpers.py tun-fd-launch NAME CONFIG SYBAU
                                        open a TUN like Android does, run the core on its fd
"""
import hashlib
import http.server
import os
import socket
import socketserver
import struct
import sys
import threading
import urllib.request

BLOB = os.urandom(8 * 1024 * 1024)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = BLOB if self.path == "/blob" else self.client_address[0].encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Blob-Sha256", hashlib.sha256(BLOB).hexdigest())
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def http_server(addrs):
    servers = [Server((a, 8080), Handler) for a in addrs]
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    servers[0].serve_forever()


def udp_echo(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, 9000))
    while True:
        data, peer = s.recvfrom(65535)
        s.sendto(peer[0].encode() + b" " + data, peer)


def udp_ask(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(b"ping", (host, int(port)))
    print(s.recvfrom(65535)[0].decode())


def dns_query(name):
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)


def dns_answers(msg):
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", msg[:12])
    pos = 12
    for _ in range(qd):
        while msg[pos] != 0:
            pos += msg[pos] + 1
        pos += 5
    out = []
    for _ in range(an):
        if msg[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while msg[pos] != 0:
                pos += msg[pos] + 1
            pos += 1
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        if rtype == 1:
            out.append(socket.inet_ntoa(msg[pos:pos + 4]))
        pos += rdlen
    return flags & 0xF, out


def dns_ask(server, name, mode="udp"):
    q = dns_query(name)
    if mode == "tcp":
        s = socket.create_connection((server, 53), timeout=5)
        s.sendall(struct.pack(">H", len(q)) + q)
        n = struct.unpack(">H", s.recv(2))[0]
        msg = b""
        while len(msg) < n:
            msg += s.recv(n - len(msg))
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(q, (server, 53))
        msg = s.recvfrom(65535)[0]
    rcode, answers = dns_answers(msg)
    print(f"rcode={rcode} " + " ".join(answers))


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        body = r.read()
        expect = r.headers.get("X-Blob-Sha256")
    got = hashlib.sha256(body).hexdigest()
    print(f"{len(body)} {'ok' if got == expect else 'MISMATCH'}")




def tun_fd_launch(name, config_path, sybau):
    """Plays the platform (Android VpnService): opens and configures the
    TUN itself, then starts the core with the open descriptor."""
    import fcntl
    import json
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, 0x400454CA, struct.pack("16sH", name.encode(), 0x0001 | 0x1000))  # TUNSETIFF: IFF_TUN | IFF_NO_PI
    os.set_inheritable(fd, True)
    for cmd in (f"ip addr add 172.19.0.1/30 dev {name}", f"ip link set {name} up",
                f"ip route add 10.99.0.1/32 dev {name}"):
        if os.system(cmd) != 0:
            sys.exit(f"`{cmd}` failed")
    cfg = json.load(open(config_path))
    tun = cfg["inbounds"][0]
    for key in ("strict_route", "kill_switch", "route_exclude_address", "exclude_uid", "exclude_process"):
        tun.pop(key, None)
    tun.update({"file_descriptor": fd, "address": ["172.19.0.1/30"]})
    json.dump(cfg, open(config_path, "w"))
    os.execv(sybau, [sybau, "run", "-c", config_path])

if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    {"http-server": lambda: http_server(args), "udp-echo": lambda: udp_echo(*args),
     "udp-ask": lambda: udp_ask(*args), "dns-ask": lambda: dns_ask(*args),
     "fetch": lambda: fetch(*args), "tun-fd-launch": lambda: tun_fd_launch(*args)}[cmd]()
