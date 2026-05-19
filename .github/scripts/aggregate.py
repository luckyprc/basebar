#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Node Aggregator: Multi-source -> Latency test -> Geo filter -> Base64 + Plain
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
import maxminddb

# ============================ CONFIG ============================
SOURCES = [
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta.yaml",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity",
    # v2rayse handled dynamically in main()
]

SS_POOLS = [
    # "https://example-pool.com/ss/sub",
]

TARGET_COUNTRIES = {"HK", "TW", "JP", "SG", "MY", "KR"}
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
    if len(text) > 40 and not text.strip().startswith(("{", "[", "proxies:")):
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
            if "vmess://" in decoded or "vless://" in decoded or "trojan://" in decoded or "ss://" in decoded:
                return decoded
        except Exception:
            pass
        try:
            decoded = base64.urlsafe_b64decode(text).decode("utf-8", errors="ignore")
            if "vmess://" in decoded or "vless://" in decoded:
                return decoded
        except Exception:
            pass
    return text


# ============================ PARSE ============================

def extract_uris(text: str) -> list:
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
                userinfo = base64.b64encode(f"{p.get('cipher', 'aes-256-gcm')}:{p.get('password', '')}".encode()).decode()
                raw = f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(name)}"
                nodes.append({"raw": raw, "proto": "ss"})

        except Exception:
            continue
    return nodes


# ============================ GEO IP ============================

GEO_READER = None

def get_ip_info(ip: str) -> dict | None:
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    global GEO_READER
    if GEO_READER is None:
        db_path = "GeoLite2-Country.mmdb"
        if not Path(db_path).exists():
            db_path = "/mnt/agents/output/GeoLite2-Country.mmdb"
        try:
            GEO_READER = maxminddb.open_database(db_path)
        except Exception as e:
            log(f"[GEO DB ERR] {e}")
            GEO_CACHE[ip] = None
            return None
    try:
        rec = GEO_READER.get(ip)
        if rec and "country" in rec and "iso_code" in rec["country"]:
            cc = rec["country"]["iso_code"]
            data = {"countryCode": cc, "status": "success", "query": ip, "as": ""}
            GEO_CACHE[ip] = data
            return data
    except Exception:
        pass
    GEO_CACHE[ip] = None
    return None


# ============================ LATENCY ============================

def test_tcp(ip: str, port: int = 443, timeout: int = 2) -> float:
    try:
        t0 = time.time()
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.close()
        return (time.time() - t0) * 1000
    except Exception:
        return 99999.0


def node_tcp_ping(ip: str, port: int) -> float:
    return test_tcp(ip, int(port), LATENCY_TIMEOUT)


# ============================ V2RAYSE ============================

def get_v2rayse_urls(days_back: int = 3) -> list:
    urls = []
    today = datetime.utcnow() + timedelta(hours=8)
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
            break
    return urls


# ============================ MAIN ============================

def main():
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

    # 3. Enrich: parse IP/port
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

    # 4. Latency test first (kill dead nodes before geo lookup)
    log("[LATENCY] TCP probing raw nodes...")
    pre_alive = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ex.submit(node_tcp_ping, n["ip"], int(n["port"])): n for n in enriched}
        for fut in as_completed(futs):
            n = futs[fut]
            lat = fut.result()
            if 0 < lat <= MAX_LATENCY_MS:
                n["latency_ms"] = round(lat, 1)
                pre_alive.append(n)
            else:
                log(f"  DEAD {n['ip']}:{n['port']} {lat:.0f}ms")

    log(f"[LATENCY PASS] {len(pre_alive)} nodes")

    # 5. Geo filter (local DB, only on alive nodes)
    log("[GEO] Filtering target countries (HK/TW/JP/SG/MY/KR)...")
    geo_passed = []
    for n in pre_alive:
        ip = n["ip"]
        info = get_ip_info(ip)
        if info:
            cc = info.get("countryCode", "")
            if cc in TARGET_COUNTRIES:
                n["country"] = cc
                n["as_info"] = info.get("as", "")
                geo_passed.append(n)

    log(f"[GEO PASS] {len(geo_passed)} nodes")

    # 6. Deduplicate by raw URI
    seen = set()
    final = []
    for n in geo_passed:
        if n["raw"] not in seen:
            seen.add(n["raw"])
            final.append(n)

    log(f"[FINAL] {len(final)} unique nodes")

    # 7. Write outputs
    plain = "\n".join(n["raw"] for n in final)
    (OUT_DIR / "nodes.txt").write_text(plain, encoding="utf-8")

    b64 = base64.b64encode(plain.encode()).decode()
    (OUT_DIR / "nodes_base64.txt").write_text(b64, encoding="utf-8")
    (OUT_DIR / "sub").write_text(b64, encoding="utf-8")

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "total_raw": len(all_nodes),
        "pre_alive": len(pre_alive),
        "geo_filtered": len(geo_passed),
        "final_unique": len(final),
        "countries": {},
    }
    for n in final:
        cc = n.get("country", "??")
        report["countries"][cc] = report["countries"].get(cc, 0) + 1

    (OUT_DIR / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    log("\n========== SUMMARY ==========")
    log(f"Raw fetched   : {len(all_nodes)}")
    log(f"Latency pass  : {len(pre_alive)}")
    log(f"Geo passed    : {len(geo_passed)}")
    log(f"Final unique  : {len(final)}")
    log("Countries     : " + json.dumps(report["countries"], ensure_ascii=False))
    log("Outputs       : output/nodes.txt | output/nodes_base64.txt | output/sub")
    log("==============================")

    if len(final) == 0:
        log("[WARN] Zero nodes survived filtering.")
        sys.exit(0)


if __name__ == "__main__":
    main()
