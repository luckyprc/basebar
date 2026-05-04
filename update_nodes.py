#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点聚合器
- 聚合多源站
- 去重（地址+端口+协议）
- TCP 延迟检测（<250ms 保留）
- HTTP 网页延迟检测（<250ms 保留）
- IP 地域硬过滤（只保留亚洲、德国、法国）
- 输出明文订阅（每行一个节点链接）
"""

import base64
import json
import os
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

import requests
import yaml


# ==================== 配置区 ====================

# 目标输出目录
OUTPUT_DIR = "output"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "v2ray.txt")

# 延迟阈值（毫秒）
TCP_LATENCY_THRESHOLD = 250
HTTP_LATENCY_THRESHOLD = 250
# HTTP 连通性检测 URL
HTTP_CHECK_URL = "http://connectivitycheck.platform.hicloud.com/generate_204"

# TCP 连接超时（秒）
TCP_TIMEOUT = 3
# 延迟测试线程数
MAX_WORKERS = 64

# 允许的地域：亚洲国家代码 (ISO 3166-1 alpha-2) + 德国(DE) + 法国(FR)
ASIA_COUNTRY_CODES = {
    "CN", "JP", "KR", "SG", "HK", "TW", "MY", "TH", "VN", "ID", "PH", "IN", "AE",
    "TR", "KH", "LA", "MM", "BD", "LK", "NP", "PK", "MN", "MO", "BN", "TL",
    "KZ", "KG", "UZ", "TJ", "TM", "GE", "AM", "AZ", "CY", "IL", "JO", "KW",
    "LB", "OM", "QA", "SA", "YE", "BH", "IQ", "IR", "PS", "SY", "AF", "BT", "MV", "IO"
}
ALLOWED_COUNTRY_CODES = ASIA_COUNTRY_CODES | {"DE", "FR"}

# 亚洲国家英文名称（匹配 ip-api 返回的 country 字段）
ASIA_COUNTRY_NAMES = {
    "China", "Japan", "Korea", "South Korea", "Republic of Korea", "Singapore",
    "Hong Kong", "Taiwan", "Malaysia", "Thailand", "Vietnam", "Indonesia",
    "Philippines", "India", "United Arab Emirates", "Turkey", "Cambodia",
    "Laos", "Myanmar", "Burma", "Bangladesh", "Sri Lanka", "Nepal", "Pakistan",
    "Mongolia", "Macao", "Macau", "Brunei", "Timor-Leste", "East Timor",
    "Kazakhstan", "Kyrgyzstan", "Uzbekistan", "Tajikistan", "Turkmenistan",
    "Georgia", "Armenia", "Azerbaijan", "Cyprus", "Israel", "Jordan", "Kuwait",
    "Lebanon", "Oman", "Qatar", "Saudi Arabia", "Yemen", "Bahrain", "Iraq",
    "Iran", "Palestine", "Syria", "Afghanistan", "Bhutan", "Maldives",
    "British Indian Ocean Territory",
}
ALLOWED_COUNTRY_NAMES = ASIA_COUNTRY_NAMES | {"Germany", "France"}

# 源站列表（自动处理 GitHub 链接转 raw）
SOURCES = [
    # 用户指定源
    "http://comm.cczzuu.top/node/{date}-v2ray.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/EternityAir",
    "https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/{date}.txt",
    "https://raw.githubusercontent.com/Fukki-Z/nodefree/main/{date}.txt",
    "https://raw.githubusercontent.com/FiFier/v2rayShare/main/{date}.txt",
    "https://raw.githubusercontent.com/colatiger/v2ray-nodes/master/{date}.txt",
    "https://raw.githubusercontent.com/ssrsub/ssr/master/{date}.txt",
    "https://raw.githubusercontent.com/iwxf/free-v2ray/master/{date}.txt",
    "https://raw.githubusercontent.com/ldir92664/Vmess-Actions/main/{date}.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/{date}.txt",
    "https://raw.githubusercontent.com/wrfree/free/main/{date}.txt",
    "https://raw.githubusercontent.com/anaer/Sub/main/{date}.txt",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/misersun/config003/main/{date}.txt",
    "https://clash.221207.xyz/pubclashyaml",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/jikelonglie/meskell/master/{date}.txt",
    "https://raw.githubusercontent.com/MOnday9907/v2ray/master/{date}.txt",
    "https://raw.githubusercontent.com/Jia-Pingwa/free-v2ray-merge/master/{date}.txt",
]

# 日期占位符格式（YYYYMMDD）
DATE_FMT = "%Y%m%d"


# ==================== 工具函数 ====================

def get_today_str() -> str:
    return time.strftime(DATE_FMT, time.localtime())


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def fetch_url(url: str, retries: int = 2) -> Optional[str]:
    """抓取 URL 内容，失败重试"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0",
    }
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                return resp.text
        except Exception as e:
            if attempt == retries:
                print(f"[ERR] Fetch failed after {retries+1} attempts: {url} -> {e}")
                return None
            time.sleep(1)
    return None


def decode_base64(data: str) -> str:
    """兼容 Base64 解码（自动补 padding）"""
    try:
        data = data.strip()
        pad = 4 - len(data) % 4
        if pad != 4:
            data += "=" * pad
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_host_from_node(node_url: str) -> Optional[str]:
    """从各种协议链接中提取服务器地址（域名或 IP）"""
    try:
        if node_url.startswith("vmess://"):
            b64 = node_url[8:]
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += "=" * pad
            cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            return cfg.get("add") or cfg.get("host")
        elif node_url.startswith("ss://"):
            parsed = urllib.parse.urlparse(node_url)
            if parsed.hostname:
                return parsed.hostname
            b64_part = node_url[5:].split("#")[0].split("@")[0]
            decoded = decode_base64(b64_part)
            if "@" in decoded:
                return decoded.split("@")[1].split(":")[0]
        elif node_url.startswith("ssr://"):
            decoded = decode_base64(node_url[6:])
            parts = decoded.split(":")
            if len(parts) >= 2:
                return parts[0]
        elif node_url.startswith("trojan://") or node_url.startswith("vless://"):
            parsed = urllib.parse.urlparse(node_url)
            return parsed.hostname
        return None
    except Exception:
        return None


def extract_port_from_node(node_url: str) -> Optional[int]:
    """提取端口"""
    try:
        if node_url.startswith("vmess://"):
            b64 = node_url[8:]
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += "=" * pad
            cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            return int(cfg.get("port", 0))
        elif node_url.startswith(("ss://", "trojan://", "vless://")):
            parsed = urllib.parse.urlparse(node_url)
            return parsed.port
        elif node_url.startswith("ssr://"):
            decoded = decode_base64(node_url[6:])
            parts = decoded.split(":")
            if len(parts) >= 2:
                return int(parts[1])
        return None
    except Exception:
        return None


def get_ip_from_host(host: str) -> Optional[str]:
    """域名解析为 IP（简单 DNS 解析）"""
    if not host:
        return None
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return host
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def query_ip_region(ip: str) -> Optional[Dict]:
    """查询 IP 地理位置（使用 ip-api.com）"""
    if not ip:
        return None
    # 内网 IP 跳过
    if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.", "127.")):
        return None
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,isp,query&lang=zh-CN"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return None


def is_allowed_region(region_data: Optional[Dict]) -> bool:
    """硬过滤：只保留亚洲、德国、法国节点"""
    if not region_data:
        return False
    cc = region_data.get("countryCode", "")
    cn = region_data.get("country", "")
    if cc in ALLOWED_COUNTRY_CODES:
        return True
    if cn in ALLOWED_COUNTRY_NAMES:
        return True
    return False


def tcp_latency_test(host: str, port: int) -> Optional[float]:
    """TCP 连接延迟测试（毫秒），返回 None 表示超时/失败"""
    if not host or not port:
        return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        start = time.time()
        result = sock.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        sock.close()
        if result == 0 and elapsed < TCP_LATENCY_THRESHOLD:
            return round(elapsed, 2)
        return None
    except Exception:
        return None


def http_latency_test() -> Optional[float]:
    """HTTP 网页延迟测试（runner 直连华为云连通性检测）"""
    try:
        start = time.time()
        resp = requests.get(HTTP_CHECK_URL, timeout=5)
        elapsed = (time.time() - start) * 1000
        if resp.status_code == 204 and elapsed < HTTP_LATENCY_THRESHOLD:
            return round(elapsed, 2)
        return None
    except Exception:
        return None


def parse_subscribe_content(text: str) -> List[str]:
    """解析订阅内容，提取节点链接"""
    nodes = []
    if not text:
        return nodes
    
    decoded = decode_base64(text)
    if decoded and ("://" in decoded):
        text = decoded
    
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vmess://", "ss://", "ssr://", "trojan://", "vless://")):
            nodes.append(line)
    
    if not nodes and ("proxies:" in text or "Proxy:" in text):
        try:
            data = yaml.safe_load(text)
            proxies = data.get("proxies", []) if isinstance(data, dict) else []
            for p in proxies:
                if not isinstance(p, dict):
                    continue
                proto = p.get("type", "").lower()
                if proto == "vmess":
                    cfg = {
                        "v": "2", "ps": p.get("name", "vmess"),
                        "add": p.get("server"), "port": str(p.get("port")),
                        "id": p.get("uuid"), "aid": str(p.get("alterId", 0)),
                        "scy": p.get("cipher", "auto"), "net": p.get("network", "tcp"),
                        "type": "none", "host": p.get("ws-opts", {}).get("headers", {}).get("Host", ""),
                        "path": p.get("ws-opts", {}).get("path", ""),
                        "tls": "tls" if p.get("tls") else ""
                    }
                    nodes.append("vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode())
                elif proto == "ss":
                    userinfo = base64.b64encode(f"{p.get('cipher')}:{p.get('password')}".encode()).decode()
                    nodes.append(f"ss://{userinfo}@{p.get('server')}:{p.get('port')}")
                elif proto == "trojan":
                    nodes.append(f"trojan://{p.get('password')}@{p.get('server')}:{p.get('port')}?sni={p.get('sni', '')}")
        except Exception as e:
            print(f"[WARN] YAML parse error: {e}")
    
    return nodes


def get_source_urls() -> List[str]:
    """生成当天源站 URL"""
    today = get_today_str()
    urls = []
    for src in SOURCES:
        url = src.replace("{date}", today)
        urls.append(url)
    return urls


# ==================== 主流程 ====================

def main():
    ensure_dir(OUTPUT_DIR)
    today = get_today_str()
    
    print(f"=== Node Aggregator Started | Date: {today} ===")
    
    # 1. 抓取所有源站
    all_nodes: List[str] = []
    source_urls = get_source_urls()
    
    for url in source_urls:
        print(f"[FETCH] {url}")
        content = fetch_url(url)
        if content:
            nodes = parse_subscribe_content(content)
            print(f"  -> Got {len(nodes)} nodes")
            all_nodes.extend(nodes)
        else:
            print(f"  -> Failed or empty")
    
    print(f"[INFO] Total raw nodes: {len(all_nodes)}")
    if not all_nodes:
        print("[WARN] No nodes fetched, aborting.")
        open(OUTPUT_FILE, "w").close()
        return
    
    # 2. 去重（基于 协议+地址+端口 的指纹）
    seen: Set[str] = set()
    unique_nodes: List[str] = []
    
    for node in all_nodes:
        host = extract_host_from_node(node)
        port = extract_port_from_node(node)
        proto = node.split("://")[0] if "://" in node else "unknown"
        fingerprint = f"{proto}://{host}:{port}"
        
        if fingerprint not in seen and host and port:
            seen.add(fingerprint)
            unique_nodes.append(node)
    
    print(f"[INFO] After dedup: {len(unique_nodes)}")
    
    # 3. TCP 延迟测试（并发）
    tcp_passed: List[Tuple[str, float]] = []  # (node, tcp_latency)
    node_meta: List[Tuple[str, str, Optional[str], int]] = []
    
    for node in unique_nodes:
        host = extract_host_from_node(node)
        port = extract_port_from_node(node)
        ip = get_ip_from_host(host) if host else None
        if host and port:
            node_meta.append((node, host, ip, port))
    
    print(f"[TEST] TCP latency testing {len(node_meta)} nodes (threshold {TCP_LATENCY_THRESHOLD}ms)...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {}
        for node, host, ip, port in node_meta:
            target_ip = ip or host
            future = executor.submit(tcp_latency_test, target_ip, port)
            future_to_node[future] = (node, host, ip, port)
        
        for future in as_completed(future_to_node):
            node, host, ip, port = future_to_node[future]
            latency = future.result()
            if latency is not None:
                tcp_passed.append((node, latency))
    
    print(f"[INFO] After TCP latency filter: {len(tcp_passed)}")
    if not tcp_passed:
        print("[WARN] No nodes passed TCP latency test, aborting.")
        open(OUTPUT_FILE, "w").close()
        return
    
    # 4. HTTP 网页延迟测试（runner 网络环境质量门槛）
    print(f"[TEST] HTTP latency check ({HTTP_CHECK_URL}, threshold {HTTP_LATENCY_THRESHOLD}ms)...")
    http_latency = http_latency_test()
    if http_latency is None:
        print("[WARN] HTTP latency check failed or exceeds threshold. Aborting.")
        open(OUTPUT_FILE, "w").close()
        return
    print(f"[OK] HTTP latency: {http_latency}ms")
    
    # 5. IP 地域查询 & 硬过滤（只保留亚洲 + 德国 + 法国）
    print(f"[GEO] Querying IP regions and filtering allowed regions...")
    
    region_results: Dict[str, Optional[Dict]] = {}
    ips_to_query: Set[str] = set()
    
    for node, _ in tcp_passed:
        host = extract_host_from_node(node)
        ip = get_ip_from_host(host)
        if ip and ip not in region_results:
            ips_to_query.add(ip)
    
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_ip = {}
        for ip in ips_to_query:
            future = executor.submit(query_ip_region, ip)
            future_to_ip[future] = ip
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            region_results[ip] = future.result()
            time.sleep(0.05)
    
    allowed_nodes: List[Tuple[str, float]] = []
    for node, tcp_lat in tcp_passed:
        host = extract_host_from_node(node)
        ip = get_ip_from_host(host)
        region_data = region_results.get(ip) if ip else None
        if is_allowed_region(region_data):
            allowed_nodes.append((node, tcp_lat))
    
    print(f"[INFO] After region filter (Asia + DE/FR): {len(allowed_nodes)}")
    if not allowed_nodes:
        print("[WARN] No nodes in allowed regions, aborting.")
        open(OUTPUT_FILE, "w").close()
        return
    
    # 6. 排序：按 TCP 延迟升序
    allowed_nodes.sort(key=lambda x: x[1])
    
    # 7. 生成订阅文件（明文，每行一个节点）
    node_text = "\n".join([n for n, _ in allowed_nodes])
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(node_text)
    
    print(f"[OK] Output: {OUTPUT_FILE}")
    print(f"[OK] Total qualified: {len(allowed_nodes)} (HTTP baseline: {http_latency}ms)")
    for i, (node, lat) in enumerate(allowed_nodes[:5], 1):
        host = extract_host_from_node(node)
        print(f"  TOP{i}: {host} | TCP:{lat}ms")


if __name__ == "__main__":
    main()
