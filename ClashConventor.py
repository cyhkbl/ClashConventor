#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clash_to_links.py
Read a Clash YAML (clash.yaml) and convert proxies to various share URI formats:
ss://, vmess://, trojan://, vless://, ssr://, hy2:// (hysteria2).
Output -> clash.txt
"""

import os
import sys
import yaml
import json
import base64
import urllib.parse
from typing import Dict, Any, List, Tuple

INPUT_FILE = "clash.yaml"
OUTPUT_FILE = "clash.txt"

def b64_no_newline(s: str) -> str:
    return base64.b64encode(s.encode('utf-8')).decode('utf-8').replace('\n', '')

def safe_name_tag(name: str) -> str:
    return urllib.parse.quote(name or "", safe='')

def quote(val: str) -> str:
    return urllib.parse.quote_plus(val or "")

def encode_vmess(p: Dict[str, Any]) -> str:
    # vmess JSON fields are fairly standard; include common keys
    vm = {
        "v": "2",
        "ps": p.get("name", ""),
        "add": p.get("server") or p.get("host") or p.get("address") or "",
        "port": str(p.get("port", "") or ""),
        "id": p.get("uuid") or p.get("id") or p.get("user") or "",
        "aid": str(p.get("alterId") or p.get("aid") or 0),
        "net": p.get("network") or p.get("net") or "tcp",
        "type": p.get("vmess-type") or "", # Removed 'type0' as it's not a standard Clash Vmess field
        "host": "",
        "path": "",
        "tls": ""
    }
    # ws options
    ws = p.get("ws-opts") or p.get("ws_opts") or p.get("ws-headers") or {}
    if isinstance(ws, dict):
        vm["path"] = ws.get("path") or vm["path"]
        headers = ws.get("headers") or {}
        vm["host"] = headers.get("Host") or headers.get("host") or vm["host"]
    vm["path"] = p.get("path") or p.get("ws-path") or vm["path"]
    vm["host"] = p.get("servername") or p.get("sni") or p.get("host") or vm["host"]
    if p.get("tls") or p.get("skip-cert-verify") or (p.get("tls", False) is True):
        vm["tls"] = "tls"
    json_str = json.dumps(vm, separators=(",", ":"), ensure_ascii=False)
    return "vmess://" + b64_no_newline(json_str)

def encode_ss(p: Dict[str, Any]) -> List[str]:
    # produce two common variants for ss
    server = p.get("server") or p.get("host") or p.get("address") or ""
    port = str(p.get("port", "") or "")
    method = p.get("cipher") or p.get("method") or p.get("encrypt-method") or ""
    password = p.get("password") or p.get("psw") or p.get("pass") or ""
    name = p.get("name") or ""
    if not (server and port and method and password):
        raise ValueError("missing required SS fields")
    info = f"{method}:{password}"
    b1 = b64_no_newline(info)
    uri1 = f"ss://{b1}@{server}:{port}#{safe_name_tag(name)}"
    # alternative: base64(method:password@host:port)
    b2 = b64_no_newline(f"{method}:{password}@{server}:{port}")
    uri2 = f"ss://{b2}#{safe_name_tag(name)}"
    return [uri1, uri2]

def encode_trojan(p: Dict[str, Any]) -> str:
    password = p.get("password") or p.get("pass") or p.get("psw") or ""
    server = p.get("server") or p.get("host") or ""
    port = str(p.get("port", "") or "")
    if not (password and server and port):
        raise ValueError("missing required Trojan fields")
    sni = p.get("servername") or p.get("sni") or ""
    query = f"?sni={urllib.parse.quote(sni)}" if sni else ""
    return f"trojan://{urllib.parse.quote(password)}@{server}:{port}{query}#{safe_name_tag(p.get('name',''))}"

def encode_vless(p: Dict[str, Any]) -> str:
    # vless://<id>@host:port?encryption=none&security=tls&type=ws&host=...&path=...#name
    server = p.get("server") or p.get("host") or ""
    port = str(p.get("port", "") or "")
    uid = p.get("uuid") or p.get("id") or ""
    if not (server and port and uid):
        raise ValueError("missing required VLESS fields (server/port/uuid)")
    qs = {}
    # encryption param (common default none) - VLESS typically uses 'none'
    qs["encryption"] = "none"
    # tls/security
    if p.get("tls") or p.get("security") == "tls":
        qs["security"] = "tls"
    # network transport
    net = p.get("network") or p.get("net") or ""
    if net:
        qs["type"] = net
    # extra fields
    if p.get("flow"):
        qs["flow"] = p.get("flow")
    # host/path for ws
    ws = p.get("ws-opts") or p.get("ws_opts") or {}
    if isinstance(ws, dict):
        path = ws.get("path") or p.get("path") or ""
        host = (ws.get("headers") or {}).get("Host") or p.get("servername") or p.get("sni") or ""
    else:
        path = p.get("path") or ""
        host = p.get("servername") or p.get("sni") or p.get("host") or ""
    if host:
        qs["host"] = host
    if path:
        qs["path"] = path
    query = "&".join(f"{k}={quote(str(v))}" for k,v in qs.items())
    return f"vless://{urllib.parse.quote(uid)}@{server}:{port}{('?' + query) if query else ''}#{safe_name_tag(p.get('name',''))}"

def encode_hy2(p: Dict[str, Any]) -> str:
    # hysteria2/hy2 URI: hysteria2://[auth@]host:port/?key=value...
    # docs: hysteria2 uses scheme hysteria2 or hy2. We'll map common fields into query params.
    server = p.get("server") or p.get("host") or ""
    port = str(p.get("port", "") or "")
    if not (server and port):
        raise ValueError("missing required hysteria2 fields (server/port)")
    # auth may be username:password or password
    auth = p.get("auth") or p.get("password") or p.get("user") or ""
    # collect query params (map common hysteria2 fields)
    params = {}
    if p.get("obfs"):
        params["obfs"] = p.get("obfs")
    if p.get("obfs-password") or p.get("obfs_password"):
        params["obfs-password"] = p.get("obfs-password") or p.get("obfs_password")
    if p.get("alpn"):
        params["alpn"] = p.get("alpn")
    if p.get("sni"):
        params["sni"] = p.get("sni")
    if p.get("tls"):
        params["tls"] = "1"
    # add other keys present
    for k in ("udp", "up_mbps", "down_mbps"):
        if k in p:
            params[k] = str(p[k])
    query = "&".join(f"{k}={quote(str(v))}" for k,v in params.items())
    authpart = urllib.parse.quote(auth) + "@" if auth else ""
    # Hysteria2 scheme is typically fixed as 'hysteria2' or 'hy2'
    scheme = "hysteria2"
    return f"{scheme}://{authpart}{server}:{port}{('?' + query) if query else ''}#{safe_name_tag(p.get('name',''))}"

def encode_ssr(p: Dict[str, Any]) -> str:
    # SSR: base64 of "host:port:protocol:method:obfs:base64(password)/?params"
    server = p.get("server") or p.get("host") or ""
    port = str(p.get("port", "") or "")
    protocol = p.get("protocol") or p.get("ssr-protocol") or "origin"
    method = p.get("method") or p.get("cipher") or ""
    obfs = p.get("obfs") or "plain" # 'obfsparam' is handled in params
    password = p.get("password") or p.get("psw") or ""
    if not (server and port and method and password):
        raise ValueError("missing required SSR fields")
    password_b64 = b64_no_newline(password)
    base = f"{server}:{port}:{protocol}:{method}:{obfs}:{password_b64}"
    # params (like obfsparam, protoparam, remarks, group)
    params = {}
    if p.get("obfsparam"):
        params["obfsparam"] = quote(p.get("obfsparam"))
    if p.get("protoparam"):
        params["protoparam"] = quote(p.get("protoparam"))
    if p.get("remarks"):
        params["remarks"] = quote(p.get("remarks"))
    if p.get("group"):
        params["group"] = quote(p.get("group"))
    param_str = ""
    if params:
        param_str = "/?" + "&".join(f"{k}={v}" for k,v in params.items())
    final = base + param_str
    return "ssr://" + b64_no_newline(final)

def find_proxies(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Try common clash locations
    proxies = []
    if isinstance(data, dict):
        if "proxies" in data and isinstance(data["proxies"], list):
            proxies = data["proxies"]
        else:
            # proxy providers may nest proxies
            if "proxy-providers" in data and isinstance(data["proxy-providers"], dict):
                for v in data["proxy-providers"].values():
                    if isinstance(v, dict) and "proxies" in v and isinstance(v["proxies"], list):
                        proxies.extend(v["proxies"])
            # some configs use 'proxy' or 'Proxy' etc:
            if "Proxy" in data and isinstance(data["Proxy"], list):
                proxies.extend(data["Proxy"])
            if "proxy" in data and isinstance(data["proxy"], list):
                proxies.extend(data["proxy"])
    return proxies

def convert_all(proxies: List[Dict[str, Any]]) -> Tuple[List[Tuple[str,str]], List[str]]:
    converted = []
    notes = []
    for p in proxies:
        try:
            ptype = (p.get("type") or "").lower()
            name = p.get("name") or p.get("tag") or p.get("remark") or "unnamed"
            if ptype == "vmess":
                converted.append((name, encode_vmess(p)))
            elif ptype in ("ss", "shadowsocks"):
                uris = encode_ss(p)
                for i,uri in enumerate(uris):
                    label = name if i==0 else f"{name} (alt)"
                    converted.append((label, uri))
            elif ptype == "trojan":
                converted.append((name, encode_trojan(p)))
            elif ptype == "vless":
                converted.append((name, encode_vless(p)))
            elif ptype in ("hysteria2", "hy2", "hysteria"):
                converted.append((name, encode_hy2(p)))
            elif ptype in ("ssr","shadowsocksr"):
                converted.append((name, encode_ssr(p)))
            else:
                notes.append(f"Skipped '{name}': unsupported or unknown type '{ptype}'.")
        except Exception as e:
            notes.append(f"Failed to convert '{p.get('name','unnamed')}': {e}")
    return converted, notes

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Input file '{INPUT_FILE}' not found. Put your Clash YAML at this path.", file=sys.stderr)
        sys.exit(2)

    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    proxies = find_proxies(data)
    print(f"Found {len(proxies)} proxies in {INPUT_FILE}.")
    converted, notes = convert_all(proxies)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out:
        out.write("# Converted proxy URIs from clash.yaml\n\n")
        for name, uri in converted:
            out.write(f"{name}\n{uri}\n\n")
        if notes:
            out.write("\n# Notes / Errors\n")
            for n in notes:
                out.write(n + "\n")

    print(f"Wrote {len(converted)} URIs to {OUTPUT_FILE}.")
    if notes:
        print(f"Encountered {len(notes)} notes/errors. See the bottom of {OUTPUT_FILE} for details.")

if __name__ == "__main__":
    main()
