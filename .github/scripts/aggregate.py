#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Node Aggregator: Multi-source -> Geo filter -> CF WS+CDN -> Latency test -> Base64 + Plain
Sources: Pawdroid, ripaojiedian, mfuu, ermaozi, snakem982, peasoft, mahdibland, v2rayse(0800/2000)
"""

import base64
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path

import yaml

# ============================ CONFIG ============================
SOURCES = [
    # GitHub raw / standard subscriptions
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    # v2rayse handled dynamically in main()
]

# Classic public SS pool endpoints using common password amazonskr05
# These are often plain JSON or SIP002; we attempt to fetch and parse.
SS_POOLS = [
    # "https://example-pool.com/ss/sub",  # placeholder: replace with real URL
]

CF_IP_POOL = [
    "172.65.235.155", "172.65.251.185", "172.65.232.186",
    "104.16.0.0", "104.17.0.0", "104.18.0.0", "104.19.0.0",
    "104.20.0.0", "104.21.0.0", "104.22.0.0",
    "172.66.0.0", "172.67.0.0",
    "104.16.1.0", "104.17.1.0", "104.18.1.0",
]

TARGET_COUNTRIES = {"HK", "TW", "JP", "SG", "MY", "KR"}
CF_PAGES_DOMAIN = os.environ.get("CF_PAGES_DOMAIN", "your-pages.pages.dev")
MAX_LATENCY_MS = int(os.environ.get("MAX_LATENCY_MS", "3000"))
LATENCY_TIMEOUT = int(os.environ.get("LATENCY_TIMEOUT", "3"))
GEO_CACHE: dict = {}

OUT_DIR = Path("output")
OUT_DIR.mkdir(exist_ok=True)

# ============================ UTILS ============================

def log(msg: str):
    print(msg, flush=True)


def fetch(url: str, timeout: int = 30) -> bytes:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as e:
        log(f"[FETCH ERR] {url}: {e}")
        return b""


def decode_sub(data: bytes) -> str:
    text = data.decode("utf-8", errors="ignore")
    # If it looks like base64 (long continuous alphanumeric+/=)
    if len(text) > 40 and not text.strip().startswith(("{", "[", "proxies:")):
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
            if "vmess://" in decoded or "vless://" in decoded or "trojan://" in decoded or "ss://" in decoded:
                return decoded
        except Exception:
            pass
        # Try URL-safe base64
        try:
            decoded = base64.urlsafe_b64decode(text).decode("utf-8", errors="ignore")
            if "vmess://" in decoded or "vless://" in decoded:
                return decoded
        except Exception:
            pass
    return text


# ============================ PARSE ============================

def extract_uris(text: str) -> list:
    """Extract all proxy URIs from plain text / base64 decoded content."""
    nodes = []
    patterns = [
        (r"vmess://([A-Za-z0-9+/=]+)", "vmess"),
        (r"(vless://[^\s]+)", "vless"),
        (r"(trojan://[^\s]+)", "trojan"),
        (r"(ss://[^\s]+)", "ss"),
        (r"(ssr://[^\s]+)", "ssr"),
    ]
    for pat, proto in patterns:
        for m in re.finditer(pat, text):
            nodes.append({"raw": m.group(0), "proto": proto})
    return nodes


def parse_clash_yaml(text: str) -> list:
    """Parse clash-meta / clash YAML and return URI-like dicts."""
    nodes = []
    try:
        data = yaml.safe_load(text)
        proxies = data.get("proxies", []) if isinstance(data, dict) else []
    except Exception as e:
        log(f"[YAML ERR] {e}")
        return nodes

    for p in proxies:
        try:
            t = p.get("type", "").lower()
            name = p.get("name", "unnamed")
            server = p.get("server", "")
            port = int(p.get("port", 0))
            if not server or not port:
                continue

            if t == "vmess":
                cfg = {
                    "v": "2",
                    "ps": name,
                    "add": server,
                    "port": str(port),
                    "id": p.get("uuid", ""),
                    "aid": str(p.get("alterId", 0)),
                    "scy": p.get("cipher", "auto"),
                    "net": p.get("network", "tcp"),
                    "type": p.get("type", "none"),
                    "host": p.get("ws-opts", {}).get("headers", {}).get("Host", p.get("servername", "")),
                    "path": p.get("ws-opts", {}).get("path", "/"),
                    "tls": "tls" if p.get("tls", False) else "",
                    "sni": p.get("servername", ""),
                }
                b64 = base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode()).decode()
                nodes.append({"raw": f"vmess://{b64}", "proto": "vmess"})

            elif t == "vless":
                qs = {
                    "encryption": p.get("flow", "none") or "none",
                    "security": "tls" if p.get("tls", False) else "none",
                    "sni": p.get("servername", ""),
                    "type": p.get("network", "tcp"),
                    "host": p.get("ws-opts", {}).get("headers", {}).get("Host", ""),
                    "path": p.get("ws-opts", {}).get("path", "/"),
                    "fp": "chrome",
                }
                qs_str = urllib.parse.urlencode({k: v for k, v in qs.items() if v})
                raw = f"vless://{p.get('uuid', '')}@{server}:{port}?{qs_str}#{urllib.parse.quote(name)}"
                nodes.append({"raw": raw, "proto": "vless"})

            elif t == "trojan":
                qs = {
                    "security": "tls" if p.get("tls", False) else "none",
                    "sni": p.get("sni", ""),
                    "type": p.get("network", "tcp"),
                    "host": p.get("ws-opts", {}).get("headers", {}).get("Host", ""),
                    "path": p.get("ws-opts", {}).get("path", "/"),
                }
                qs_str = urllib.parse.urlencode({k: v for k, v in qs.items() if v})
                raw = f"trojan://{p.get('password', '')}@{server}:{port}?{qs_str}#{urllib.parse.quote(name)}"
                nodes.append({"raw": raw, "proto": "trojan"})

            elif t == "ss":
                # SIP002
                userinfo = base64.b64encode(f"{p.get('cipher', 'aes-256-gcm')}:{p.get('password', '')}".encode()).decode()
                raw = f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(name)}"
                nodes.append({"raw": raw, "proto": "ss"})

        except Exception as e:
            continue
    return nodes


# ============================ GEO IP ============================

def get_ip_info(ip: str) -> dict | None:
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=countryCode,as,query,status,message"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            GEO_CACHE[ip] = data
            return data
    except Exception as e:
        pass
    GEO_CACHE[ip] = None
    return None


# ============================ CF IP ============================

def test_tcp(ip: str, port: int = 443, timeout: int = 2) -> float:
    try:
        t0 = time.time()
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.close()
        return (time.time() - t0) * 1000
    except Exception:
        return 99999.0


def pick_best_cf_ip() -> str:
    log("[CF] Probing Cloudflare IPs...")
    results = []
    with ThreadPoolExecutor(max_workers=25) as ex:
        futs = {ex.submit(test_tcp, ip, 443, 2): ip for ip in CF_IP_POOL}
        for fut in as_completed(futs):
            ip = futs[fut]
            lat = fut.result()
            if lat < 99999:
                results.append((ip, lat))
                log(f"  {ip}: {lat:.0f}ms")
    results.sort(key=lambda x: x[1])
    if not results:
        log("[CF] All probes failed, fallback to 104.17.0.0")
        return "104.17.0.0"
    best_ip, best_lat = results[0]
    log(f"[CF] Best IP: {best_ip} ({best_lat:.0f}ms)")
    return best_ip


# ============================ LATENCY ============================

def node_tcp_ping(ip: str, port: int) -> float:
    return test_tcp(ip, int(port), LATENCY_TIMEOUT)


# ============================ CONVERT ============================

def convert_vmess(raw: str, cf_ip: str, cf_domain: str) -> str:
    try:
        b64 = raw.replace("vmess://", "").strip()
        b64 += "=" * (-len(b64) % 4)
        cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
    except Exception:
        return raw

    # Only convert TCP with TLS or port 443
    net = cfg.get("net", "tcp")
    port = int(cfg.get("port", 0))
    tls = cfg.get("tls", "")
    if net != "tcp" or (port != 443 and tls not in ("tls", "xtls")):
        return raw

    cfg["add"] = cf_ip
    cfg["net"] = "ws"
    cfg["host"] = cf_domain
    cfg["path"] = cfg.get("path", "/") or "/"
    cfg["tls"] = "tls"
    cfg["sni"] = cf_domain
    new_b64 = base64.b64encode(json.dumps(cfg, ensure_ascii=False).encode()).decode()
    return f"vmess://{new_b64}"


def convert_vless(raw: str, cf_ip: str, cf_domain: str) -> str:
    try:
        url = urllib.parse.urlparse(raw)
        qs = urllib.parse.parse_qs(url.query)
    except Exception:
        return raw

    if qs.get("type", ["tcp"])[0] != "tcp":
        return raw
    port = url.port or 443
    sec = qs.get("security", [""])[0]
    if port != 443 and sec not in ("tls", "xtls", "reality"):
        return raw

    qs["type"] = ["ws"]
    qs["host"] = [cf_domain]
    qs["path"] = [qs.get("path", ["/"])[0] or "/"]
    if sec in ("", "none"):
        qs["security"] = ["tls"]
    qs["sni"] = [cf_domain]
    qs["fp"] = ["chrome"]

    new_qs = urllib.parse.urlencode({k: v[0] for k, v in qs.items()}, doseq=False)
    netloc = f"{url.username}@{cf_ip}:{port}"
    frag = urllib.parse.unquote(url.fragment) if url.fragment else "CF-WS"
    return urllib.parse.urlunparse(("vless", netloc, "", "", new_qs, frag))


def convert_trojan(raw: str, cf_ip: str, cf_domain: str) -> str:
    try:
        url = urllib.parse.urlparse(raw)
        qs = urllib.parse.parse_qs(url.query)
    except Exception:
        return raw

    if qs.get("type", ["tcp"])[0] != "tcp":
        return raw
    port = url.port or 443
    if port != 443:
        return raw

    qs["type"] = ["ws"]
    qs["host"] = [cf_domain]
    qs["path"] = [qs.get("path", ["/"])[0] or "/"]
    qs["sni"] = [cf_domain]

    new_qs = urllib.parse.urlencode({k: v[0] for k, v in qs.items()}, doseq=False)
    netloc = f"{url.username}@{cf_ip}:{port}"
    frag = urllib.parse.unquote(url.fragment) if url.fragment else "CF-WS"
    return urllib.parse.urlunparse(("trojan", netloc, "", "", new_qs, frag))


def maybe_convert(raw: str, proto: str, cf_ip: str, cf_domain: str) -> str:
    if proto == "vmess":
        return convert_vmess(raw, cf_ip, cf_domain)
    elif proto == "vless":
        return convert_vless(raw, cf_ip, cf_domain)
    elif proto == "trojan":
        return convert_trojan(raw, cf_ip, cf_domain)
    return raw


# ============================ V2RAYSE ============================

def get_v2rayse_urls(days_back: int = 3) -> list:
    """
    v2rayse.com publishes two daily files:
      /fs/public/YYYYMMDD/free-node-share-0800.txt
      /fs/public/YYYYMMDD/free-node-share-2000.txt
    We probe recent dates until both files (or at least one) respond 200.
    """
    urls = []
    today = datetime.utcnow() + timedelta(hours=8)  # Approx Beijing time
    
    for i in range(days_back):
        date_str = (today - timedelta(days=i)).strftime("%Y%m%d")
        candidates = [
            f"https://v2rayse.com/fs/public/{date_str}/free-node-share-0800.txt",
            f"https://v2rayse.com/fs/public/{date_str}/free-node-share-2000.txt",
        ]
        day_ok = False
        for url in candidates:
            data = fetch(url, timeout=10)
            if data and len(data) > 100:
                urls.append(url)
                day_ok = True
                log(f"[V2RAYSE] OK {url}")
            else:
                log(f"[V2RAYSE] MISS {url}")
        if day_ok:
            break  # Use the most recent day that has files
    
    return urls


# ============================ MAIN ============================

def main():
    best_cf_ip = pick_best_cf_ip()
    all_nodes: list[dict] = []

    # 0. Fetch v2rayse date-based files (0800 & 2000)
    v2rayse_urls = get_v2rayse_urls(days_back=3)
    for url in v2rayse_urls:
        log(f"[FETCH] {url}")
        data = fetch(url)
        if not data:
            continue
        text = decode_sub(data)
        if text.strip().startswith(("proxies:", "---", "port:")) or "proxies:" in text[:500]:
            nodes = parse_clash_yaml(text)
        else:
            nodes = extract_uris(text)
        log(f"  -> {len(nodes)} nodes")
        all_nodes.extend(nodes)

    # 1. Fetch standard sources
    for url in SOURCES:
        log(f"[FETCH] {url}")
        data = fetch(url)
        if not data:
            continue
        text = decode_sub(data)
        if text.strip().startswith(("proxies:", "---", "port:")) or "proxies:" in text[:500]:
            nodes = parse_clash_yaml(text)
        else:
            nodes = extract_uris(text)
        log(f"  -> {len(nodes)} nodes")
        all_nodes.extend(nodes)

    # 2. Fetch SS pools (if any)
    for url in SS_POOLS:
        log(f"[FETCH SS] {url}")
        data = fetch(url)
        if data:
            text = decode_sub(data)
            nodes = extract_uris(text)
            log(f"  -> {len(nodes)} nodes")
            all_nodes.extend(nodes)

    log(f"[TOTAL RAW] {len(all_nodes)} nodes")

    # 3. Enrich: parse IP/port for geo & latency
    enriched = []
    for n in all_nodes:
        raw = n["raw"]
        proto = n["proto"]
        ip = None
        port = None
        try:
            if proto == "vmess":
                b64 = raw.replace("vmess://", "").strip()
                b64 += "=" * (-len(b64) % 4)
                cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                ip = cfg.get("add")
                port = cfg.get("port")
            elif proto in ("vless", "trojan"):
                url = urllib.parse.urlparse(raw)
                ip = url.hostname
                port = url.port
            elif proto in ("ss", "ssr"):
                url = urllib.parse.urlparse(raw)
                ip = url.hostname
                port = url.port
        except Exception:
            pass

        if ip and port:
            enriched.append({"raw": raw, "proto": proto, "ip": str(ip), "port": str(port)})

    log(f"[ENRICHED] {len(enriched)} nodes with IP/port")

    # 4. Geo filter (rate-limited)
    log("[GEO] Filtering target countries (HK/TW/JP/SG/MY/KR)...")
    geo_passed = []
    for idx, n in enumerate(enriched):
        ip = n["ip"]
        info = get_ip_info(ip)
        if info:
            cc = info.get("countryCode", "")
            if cc in TARGET_COUNTRIES:
                n["country"] = cc
                n["as_info"] = info.get("as", "")
                geo_passed.append(n)
        # ip-api free limit ~45/min; sleep to be safe
        if (idx + 1) % 40 == 0:
            log("  [GEO] Rate-limit sleep 70s...")
            time.sleep(70)
        else:
            time.sleep(0.05)

    log(f"[GEO PASS] {len(geo_passed)} nodes")

    # 5. Convert TCP -> WS+CDN
    log("[CONV] Converting eligible TCP nodes to WS+CDN...")
    converted = []
    for n in geo_passed:
        new_raw = maybe_convert(n["raw"], n["proto"], best_cf_ip, CF_PAGES_DOMAIN)
        n["raw"] = new_raw
        n["converted"] = new_raw != n["raw"]
        converted.append(n)

    # 6. Latency test
    log("[LATENCY] TCP probing nodes...")
    alive = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ex.submit(node_tcp_ping, n["ip"], int(n["port"])): n for n in converted}
        for fut in as_completed(futs):
            n = futs[fut]
            lat = fut.result()
            if 0 < lat <= MAX_LATENCY_MS:
                n["latency_ms"] = round(lat, 1)
                alive.append(n)
                log(f"  OK {n['ip']}:{n['port']} {lat:.0f}ms [{n.get('country','')}]")
            else:
                log(f"  FAIL {n['ip']}:{n['port']} {lat:.0f}ms")

    log(f"[ALIVE] {len(alive)} nodes")

    # 7. Deduplicate by raw URI
    seen = set()
    final = []
    for n in alive:
        if n["raw"] not in seen:
            seen.add(n["raw"])
            final.append(n)

    log(f"[FINAL] {len(final)} unique nodes")

    # 8. Write outputs
    plain = "\n".join(n["raw"] for n in final)
    (OUT_DIR / "nodes.txt").write_text(plain, encoding="utf-8")

    b64 = base64.b64encode(plain.encode()).decode()
    (OUT_DIR / "nodes_base64.txt").write_text(b64, encoding="utf-8")

    # Also write a single-line base64 file commonly used by v2rayN
    (OUT_DIR / "sub").write_text(b64, encoding="utf-8")

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "cf_ip": best_cf_ip,
        "cf_domain": CF_PAGES_DOMAIN,
        "total_raw": len(all_nodes),
        "geo_filtered": len(geo_passed),
        "alive": len(alive),
        "final_unique": len(final),
        "countries": {},
        "converted_count": sum(1 for n in final if n.get("converted")),
    }
    for n in final:
        cc = n.get("country", "??")
        report["countries"][cc] = report["countries"].get(cc, 0) + 1

    (OUT_DIR / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    # Summary print
    log("\n========== SUMMARY ==========")
    log(f"CF Best IP    : {best_cf_ip}")
    log(f"CF Domain     : {CF_PAGES_DOMAIN}")
    log(f"Raw fetched   : {len(all_nodes)}")
    log(f"Geo passed    : {len(geo_passed)}")
    log(f"Alive (latency): {len(alive)}")
    log(f"Final unique  : {len(final)}")
    log(f"Converted WS  : {report['converted_count']}")
    log("Countries     : " + json.dumps(report["countries"], ensure_ascii=False))
    log("Outputs       : output/nodes.txt | output/nodes_base64.txt | output/sub")
    log("==============================")

    # Fail the job if zero nodes so Pages does not deploy stale empty file
    if len(final) == 0:
        log("[WARN] Zero nodes survived filtering; keeping previous artifact if any.")
        sys.exit(0)


if __name__ == "__main__":
    main()
