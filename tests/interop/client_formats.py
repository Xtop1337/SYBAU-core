"""Client configurations in the formats of other programs.

For the `--client-format` modes of run.py: an outbound in SYBAU's format
is written the way Xray, sing-box or share links express it. The result
is checked with the real program first, then converted by `sybau convert`
/ `sybau import`. A generator returns None when the setting has no
equivalent in that format; such cases are skipped.
"""

import base64
import json
import urllib.parse


class Unsupported(Exception):
    pass


def _tls_xray(tls):
    if tls is None:
        return {}
    if tls.get("insecure") or tls.get("pinned_cert_chain_sha256"):
        raise Unsupported("Xray 26 has no allowInsecure / chain pin")
    if "fragment" in tls:
        raise Unsupported("fragment needs a separate freedom outbound")
    if "reality" in tls:
        r = tls["reality"]
        return {"security": "reality", "realitySettings": {
            "serverName": tls.get("server_name", ""), "fingerprint": tls.get("fingerprint", "chrome"),
            "publicKey": r["public_key"], "shortId": r.get("short_id", "")}}
    s = {"serverName": tls.get("server_name", "")}
    if tls.get("pinned_cert_sha256"):
        s["pinnedPeerCertSha256"] = ",".join(tls["pinned_cert_sha256"])
    if tls.get("alpn"):
        s["alpn"] = tls["alpn"]
    if tls.get("fingerprint"):
        s["fingerprint"] = tls["fingerprint"]
    return {"security": "tls", "tlsSettings": s}


def _transport_xray(t):
    if t is None:
        return {"network": "tcp"}
    kind = t["type"]
    if kind == "tcp":
        o = t["http_obfs"]
        return {"network": "tcp", "tcpSettings": {"header": {"type": "http", "request": {
            "path": [o.get("path", "/")], "headers": {"Host": o.get("host", [])}}}}}
    if kind == "ws":
        path = t.get("path", "/")
        if t.get("max_early_data"):
            if t.get("early_data_header_name") != "Sec-WebSocket-Protocol":
                raise Unsupported("Xray carries early data only in Sec-WebSocket-Protocol")
            path += f"?ed={t['max_early_data']}"
        s = {"path": path}
        if t.get("host"):
            s["host"] = t["host"]
        return {"network": "ws", "wsSettings": s}
    if kind == "httpupgrade":
        return {"network": "httpupgrade", "httpupgradeSettings": {"path": t.get("path", "/"), "host": t.get("host", "")}}
    if kind == "grpc":
        return {"network": "grpc", "grpcSettings": {"serviceName": t["service_name"], "multiMode": bool(t.get("multi_mode"))}}
    raise Unsupported(f"transport {kind} is gone from Xray 26")


def xray(ob, server, port, proxy_port):
    """A full Xray client config: SOCKS inbound and the outbound."""
    kind = ob["type"]
    addr = {"address": server, "port": port}
    if kind == "vless":
        if ob.get("packet_encoding"):
            raise Unsupported("Xray 26 has no packetEncoding")
        user = {"id": ob["uuid"], "encryption": "none"}
        if ob.get("flow"):
            user["flow"] = ob["flow"]
        settings = {"vnext": [{**addr, "users": [user]}]}
    elif kind == "vmess":
        if ob.get("global_padding") is False:
            raise Unsupported("global padding cannot be turned off in Xray")
        settings = {"vnext": [{**addr, "users": [{"id": ob["uuid"], "alterId": 0, "security": ob.get("security", "auto")}]}]}
    elif kind == "trojan":
        settings = {"servers": [{**addr, "password": ob["password"]}]}
    elif kind == "shadowsocks":
        settings = {"servers": [{**addr, "method": ob["method"], "password": ob["password"]}]}
    elif kind in ("socks", "http"):
        server_cfg = dict(addr)
        if ob.get("username"):
            server_cfg["users"] = [{"user": ob["username"], "pass": ob.get("password", "")}]
        settings = {"servers": [server_cfg]}
    else:
        raise Unsupported(kind)
    stream = {**_transport_xray(ob.get("transport")), **_tls_xray(ob.get("tls"))}
    outbound = {"tag": "proxy", "protocol": kind, "settings": settings, "streamSettings": stream}
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": proxy_port, "protocol": "socks", "settings": {"udp": True}}],
        "outbounds": [outbound],
    }


def _tls_singbox(tls, cert_path):
    if tls is None:
        return None
    if tls.get("pinned_cert_chain_sha256") or "fragment" in tls:
        raise Unsupported("no sing-box equivalent")
    t = {"enabled": True}
    if tls.get("server_name"):
        t["server_name"] = tls["server_name"]
    if tls.get("alpn"):
        t["alpn"] = tls["alpn"]
    if tls.get("insecure"):
        t["insecure"] = True
    if tls.get("pinned_cert_sha256"):
        # sing-box trusts a certificate by its PEM.
        t["certificate_path"] = cert_path
    if tls.get("fingerprint"):
        t["utls"] = {"enabled": True, "fingerprint": tls["fingerprint"]}
    if "reality" in tls:
        t["reality"] = {"enabled": True, "public_key": tls["reality"]["public_key"], "short_id": tls["reality"].get("short_id", "")}
    return t


def _transport_singbox(t):
    if t is None:
        return None
    kind = t["type"]
    if kind == "ws":
        o = {"type": "ws", "path": t.get("path", "/")}
        if t.get("host"):
            o["headers"] = {"Host": t["host"]}
        if t.get("max_early_data"):
            o["max_early_data"] = t["max_early_data"]
            if t.get("early_data_header_name"):
                o["early_data_header_name"] = t["early_data_header_name"]
        return o
    if kind == "httpupgrade":
        return {"type": "httpupgrade", "path": t.get("path", "/"), "host": t.get("host", "")}
    if kind == "grpc":
        if t.get("multi_mode"):
            raise Unsupported("sing-box has no gRPC multi mode")
        return {"type": "grpc", "service_name": t["service_name"]}
    if kind == "http":
        return {"type": "http", "host": t.get("host", []), "path": t.get("path", "/")}
    raise Unsupported(f"transport {kind}")


def singbox(ob, server, port, proxy_port, cert_path):
    kind = ob["type"]
    o = {"type": kind, "tag": "proxy", "server": server, "server_port": port}
    for key in ("uuid", "flow", "packet_encoding", "password", "method", "username"):
        if key in ob:
            o[key] = ob[key]
    if kind == "vmess":
        o["security"] = ob.get("security", "auto")
        o["alter_id"] = 0
        if ob.get("global_padding") is False:
            o["global_padding"] = False
        else:
            o["global_padding"] = True
    if kind == "socks":
        o["version"] = "5"
    tls = _tls_singbox(ob.get("tls"), cert_path)
    if tls:
        o["tls"] = tls
    transport = _transport_singbox(ob.get("transport"))
    if transport:
        o["transport"] = transport
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": proxy_port}],
        "outbounds": [o],
    }


def _query(params):
    return urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "")}, quote_via=urllib.parse.quote)


def _link_common(ob):
    p = {}
    tls = ob.get("tls")
    if tls:
        if "fragment" in tls or tls.get("pinned_cert_chain_sha256"):
            raise Unsupported("not expressible in a link")
        if "reality" in tls:
            p.update(security="reality", pbk=tls["reality"]["public_key"], sid=tls["reality"].get("short_id", ""))
        else:
            p["security"] = "tls"
        p["sni"] = tls.get("server_name")
        p["fp"] = tls.get("fingerprint")
        if tls.get("alpn"):
            p["alpn"] = ",".join(tls["alpn"])
        if tls.get("insecure"):
            p["allowInsecure"] = "1"
        if tls.get("pinned_cert_sha256"):
            p["pcs"] = ",".join(tls["pinned_cert_sha256"])
    else:
        p["security"] = "none"
    t = ob.get("transport")
    if t is None:
        p["type"] = "tcp"
    elif t["type"] == "tcp":
        o = t["http_obfs"]
        p.update(type="tcp", headerType="http", host=",".join(o.get("host", [])), path=o.get("path", "/"))
    elif t["type"] == "ws":
        path = t.get("path", "/")
        if t.get("max_early_data"):
            if t.get("early_data_header_name") != "Sec-WebSocket-Protocol":
                raise Unsupported("links carry early data only as ?ed=")
            path += f"?ed={t['max_early_data']}"
        p.update(type="ws", path=path, host=t.get("host"))
    elif t["type"] == "httpupgrade":
        p.update(type="httpupgrade", path=t.get("path", "/"), host=t.get("host"))
    elif t["type"] == "grpc":
        p.update(type="grpc", serviceName=t["service_name"], mode="multi" if t.get("multi_mode") else "gun")
    elif t["type"] == "http":
        p.update(type="http", path=t.get("path", "/"), host=",".join(t.get("host", [])))
    return p


def link(ob, server, port):
    kind = ob["type"]
    name = urllib.parse.quote("interop case")
    if kind == "vless":
        p = _link_common(ob)
        p.update(encryption="none", flow=ob.get("flow"), packetEncoding=ob.get("packet_encoding"))
        return f"vless://{ob['uuid']}@{server}:{port}?{_query(p)}#{name}"
    if kind == "trojan":
        p = _link_common(ob)
        return f"trojan://{urllib.parse.quote(ob['password'], safe='')}@{server}:{port}?{_query(p)}#{name}"
    if kind == "shadowsocks":
        userinfo = base64.urlsafe_b64encode(f"{ob['method']}:{ob['password']}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{port}#{name}"
    if kind == "vmess":
        if ob.get("global_padding") is False:
            raise Unsupported("no padding switch in vmess links")
        p = _link_common(ob)
        if p.get("pcs"):
            raise Unsupported("vmess links carry no pin")
        v = {"v": "2", "ps": "interop case", "add": server, "port": str(port), "id": ob["uuid"], "aid": "0",
             "scy": ob.get("security", "auto"), "net": p.get("type", "tcp"), "type": p.get("headerType", "none"),
             "host": p.get("host") or "", "path": p.get("path") or p.get("serviceName") or "",
             "tls": "" if p["security"] == "none" else p["security"], "sni": p.get("sni") or "",
             "alpn": p.get("alpn") or "", "fp": p.get("fp") or ""}
        if p.get("allowInsecure"):
            v["allowInsecure"] = "1"
        return "vmess://" + base64.b64encode(json.dumps(v).encode()).decode()
    raise Unsupported(f"{kind} has no share link")
