#!/usr/bin/env python3
"""
优化版节点聚合脚本
改进点：
1. 异步并发测试（大幅提升速度）
2. TCP+TLS 双层测试
3. 智能分级输出（按延迟分档）
4. 放宽地理限制，补充低延迟节点
5. 限制输出数量，适配 Hiddify
"""

import os
import re
import json
import base64
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import maxminddb

# ============ 配置 ============
LATENCY_TIMEOUT = int(os.getenv("LATENCY_TIMEOUT", "2"))
MAX_LATENCY_MS = int(os.getenv("MAX_LATENCY_MS", "2000"))
GEO_COUNTRIES = os.getenv("GEO_COUNTRIES", "HK,TW,JP,SG,MY,KR").split(",")
REAL_TEST_URL = os.getenv("REAL_TEST_URL", "https://www.google.com/generate_204")
REAL_TEST_TIMEOUT = int(os.getenv("REAL_TEST_TIMEOUT", "5"))

# 订阅源
SOURCES = [
    {"type": "v2rayse", "url": "https://v2rayse.com/fs/public/{date}/free-node-share-0800.txt"},
    {"type": "v2rayse", "url": "https://v2rayse.com/fs/public/{date}/free-node-share-2000.txt"},
    {"type": "raw", "url": "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"},
    {"type": "raw", "url": "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray"},
    {"type": "raw", "url": "https://glasspanelfree.betsyangel.ndjp.net/sub"},
    {"type": "raw", "url": "https://liyan1236.ccwu.cc/sub?token=1e33160d4f679f921a2fc44c83b94c33"},
    {"type": "raw", "url": "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2"},
    {"type": "raw", "url": "https://raw.githubusercontent.com/Barabama/FreeNodes/main/nodes/merged.txt"},
]

# ============ 节点解析 ============

def decode_base64(data: str) -> str:
    """增强版 Base64 解码"""
    data = data.strip()
    if not data:
        return ""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def extract_nodes(text: str) -> list:
    """从文本中提取所有节点链接"""
    text = decode_base64(text) if not text.startswith(('vmess://', 'vless://', 'trojan://', 'ss://')) else text
    pattern = r'(vmess://|vless://|trojan://|ss://|ssr://)[^\s]+'
    return re.findall(pattern, text)

def parse_node_url(url: str) -> dict:
    """解析节点 URL，提取 IP/端口/协议"""
    try:
        if url.startswith('vmess://'):
            json_str = decode_base64(url[8:])
            cfg = json.loads(json_str)
            return {
                "type": "vmess",
                "ip": cfg.get("add", ""),
                "port": int(cfg.get("port", 0)),
                "ps": cfg.get("ps", "vmess"),
                "raw": url
            }
        elif url.startswith(('vless://', 'trojan://', 'ss://')):
            rest = url.split('://', 1)[1]
            if '#' in rest:
                rest, remark = rest.split('#', 1)
                remark = urllib.parse.unquote(remark)
            else:
                remark = "node"

            if '@' in rest:
                _, addr = rest.split('@', 1)
            else:
                addr = rest

            if '?' in addr:
                addr = addr.split('?', 1)[0]
            if ':' in addr:
                ip, port_str = addr.rsplit(':', 1)
                if ip.startswith('['):
                    ip = ip[1:].split(']', 1)[0]
                port = int(port_str.split('/')[0])
            else:
                ip = addr
                port = 443

            proto = url.split('://')[0]
            return {
                "type": proto,
                "ip": ip,
                "port": port,
                "ps": remark,
                "raw": url
            }
    except Exception:
        return None
    return None

# ============ 网络测试 ============

def tcp_test(ip: str, port: int) -> int:
    """TCP 连接测试，返回延迟(ms)，失败返回 99999"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(LATENCY_TIMEOUT)
        start = datetime.now()
        sock.connect((ip, port))
        latency = int((datetime.now() - start).total_seconds() * 1000)
        sock.close()
        return latency
    except Exception:
        return 99999

def tls_test(ip: str, port: int) -> int:
    """TLS 握手测试，返回延迟(ms)，失败返回 99999"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((ip, port), timeout=3)
        start = datetime.now()
        tls_sock = ctx.wrap_socket(sock, server_hostname=ip)
        latency = int((datetime.now() - start).total_seconds() * 1000)
        tls_sock.close()
        return latency
    except Exception:
        return 99999

def real_connect_test(node: dict) -> dict:
    """真连接测试：TCP + TLS"""
    ip, port = node["ip"], node["port"]

    # TCP 测试
    tcp_lat = tcp_test(ip, port)
    if tcp_lat == 99999 or tcp_lat > MAX_LATENCY_MS:
        return None

    node["tcp_latency"] = tcp_lat

    # TLS 测试（针对 TLS 端口）
    tls_ports = [443, 8443, 2053, 2083, 2087, 2096]
    if port in tls_ports:
        tls_lat = tls_test(ip, port)
        node["tls_latency"] = tls_lat
        if tls_lat == 99999:
            node["score"] = tcp_lat + 1000  # TLS 失败扣分
        else:
            node["score"] = tcp_lat + tls_lat
    else:
        node["tls_latency"] = 0
        node["score"] = tcp_lat

    return node

def get_country(ip: str, geo_reader) -> str:
    """查询 IP 归属国家"""
    try:
        rec = geo_reader.get(ip)
        return rec.get("country", {}).get("iso_code", "") or rec.get("registered_country", {}).get("iso_code", "")
    except Exception:
        return ""

# ============ 主流程 ============

def fetch_source(source: dict) -> list:
    """抓取单个源"""
    url = source["url"].format(date=datetime.now().strftime("%Y%m%d"))
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/plain,*/*"
            },
            timeout=15
        )
        with urllib.request.urlopen(req) as resp:
            data = resp.read().decode('utf-8', errors='ignore')
            nodes = extract_nodes(data)
            print(f"[FETCH] {url} -> {len(nodes)} nodes")
            return nodes
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"[FETCH MISS] {url}: 404")
        else:
            print(f"[FETCH ERR] {url}: HTTP {e.code}")
        return []
    except Exception as e:
        print(f"[FETCH ERR] {url}: {str(e)[:50]}")
        return []

def main():
    print("=" * 50)
    print(f"Starting aggregation at {datetime.now()}")
    print("=" * 50)

    # 1. 加载 GeoIP
    geo_reader = maxminddb.open_database("GeoLite2-Country.mmdb")

    # 2. 并发抓取所有源
    all_urls = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(fetch_source, s): s for s in SOURCES}
        for fut in as_completed(futures):
            all_urls.extend(fut.result())

    print(f"[TOTAL RAW URLs] {len(all_urls)}")

    # 3. 解析节点
    nodes = []
    for url in all_urls:
        n = parse_node_url(url)
        if n and n["ip"] and n["port"]:
            nodes.append(n)

    print(f"[PARSED] {len(nodes)} nodes with IP/port")

    # 4. IP:Port 去重
    seen = set()
    unique_nodes = []
    for n in nodes:
        key = f"{n['ip']}:{n['port']}"
        if key not in seen:
            seen.add(key)
            unique_nodes.append(n)

    print(f"[DEDUP] {len(unique_nodes)} unique endpoints (dropped {len(nodes)-len(unique_nodes)} dupes)")

    # 5. 并发 TCP+TLS 测试（并发数 100）
    alive_nodes = []
    print(f"[TEST] Testing {len(unique_nodes)} nodes with {LATENCY_TIMEOUT}s timeout...")

    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(real_connect_test, n): n for n in unique_nodes}
        for i, fut in enumerate(as_completed(futures)):
            result = fut.result()
            if result:
                alive_nodes.append(result)
                if i % 50 == 0:
                    print(f"  Progress: {i}/{len(unique_nodes)}, alive so far: {len(alive_nodes)}")

    # 按 score 排序
    alive_nodes.sort(key=lambda x: x["score"])

    print(f"[CONN PASS] {len(alive_nodes)} nodes (TCP+TLS tested)")

    # 6. Geo 过滤
    geo_passed = []
    other_nodes = []

    for n in alive_nodes:
        country = get_country(n["ip"], geo_reader)
        n["country"] = country
        if country in GEO_COUNTRIES:
            geo_passed.append(n)
        else:
            other_nodes.append(n)

    print(f"[GEO] Target countries ({','.join(GEO_COUNTRIES)}): {len(geo_passed)} nodes")

    # 亚洲节点不足时，补充欧美低延迟节点
    MIN_NODES = 50
    if len(geo_passed) < MIN_NODES:
        supplement = [n for n in other_nodes if n["tcp_latency"] < 500][:MIN_NODES - len(geo_passed)]
        geo_passed.extend(supplement)
        print(f"[GEO] Supplemented {len(supplement)} low-latency non-Asia nodes")

    geo_reader.close()

    # 7. 分级输出
    tier_a = [n for n in geo_passed if n["tcp_latency"] < 100]
    tier_b = [n for n in geo_passed if 100 <= n["tcp_latency"] < 300]
    tier_c = [n for n in geo_passed if 300 <= n["tcp_latency"] <= MAX_LATENCY_MS]

    final_nodes = tier_a + tier_b + tier_c

    # 限制总数，适配 Hiddify
    MAX_OUTPUT = 150
    final_nodes = final_nodes[:MAX_OUTPUT]

    print(f"[FINAL] {len(final_nodes)} nodes")
    print(f"  Tier A (<100ms): {len(tier_a)}")
    print(f"  Tier B (100-300ms): {len(tier_b)}")
    print(f"  Tier C (300-2000ms): {len(tier_c)}")

    # 统计国家分布
    country_dist = {}
    for n in final_nodes:
        c = n.get("country", "??")
        country_dist[c] = country_dist.get(c, 0) + 1
    print(f"  Countries: {json.dumps(country_dist, ensure_ascii=False)}")

    # 8. 输出文件
    os.makedirs("output", exist_ok=True)

    # 8.1 原始节点列表（按质量排序）
    with open("output/nodes.txt", "w", encoding="utf-8") as f:
        for n in final_nodes:
            f.write(n["raw"] + "\n")

    # 8.2 Base64 编码订阅
    raw_text = "\n".join(n["raw"] for n in final_nodes)
    b64_text = base64.b64encode(raw_text.encode()).decode()
    with open("output/nodes_base64.txt", "w") as f:
        f.write(b64_text)

    # 8.3 通用订阅格式
    with open("output/sub", "w") as f:
        f.write(b64_text)

    # 8.4 生成报告
    report = {
        "timestamp": datetime.now().isoformat(),
        "raw_fetched": len(all_urls),
        "parsed": len(nodes),
        "deduped": len(unique_nodes),
        "alive": len(alive_nodes),
        "geo_passed": len([n for n in geo_passed if n.get("country") in GEO_COUNTRIES]),
        "final": len(final_nodes),
        "tier_distribution": {
            "A": len(tier_a),
            "B": len(tier_b),
            "C": len(tier_c)
        },
        "countries": country_dist,
        "sources": [s["url"] for s in SOURCES]
    }
    with open("output/report.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("=" * 50)
    print("Outputs: output/nodes.txt | output/nodes_base64.txt | output/sub | output/report.json")
    print("=" * 50)

if __name__ == "__main__":
    main()
