#!/usr/bin/env python3
import os
import re
import sys
import requests
from datetime import datetime, timezone

CHANNEL = "Outline_Vpn"
KV_FILE = "sub.txt"

PROTOCOLS = ['vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'hysteria2://', 'hy2://', 'tuic://', 'wg://']

def log(msg):
    print(f"[{datetime.now().isoformat()}] {msg}")

def clean_html(raw):
    text = raw.replace('<br>', '\n').replace('<br/>', '\n').replace('<br />', '\n')
    text = re.sub(r'<[^>]+>', '', text)
    for old, new in {'&nbsp;': ' ', '&lt;': '<', '&gt;': '>', '&amp;': '&', '&#39;': "'", '&quot;': '"'}.items():
        text = text.replace(old, new)
    return text.strip()

def extract_nodes(text):
    nodes = []
    positions = []
    
    for proto in PROTOCOLS:
        for m in re.finditer(re.escape(proto), text):
            positions.append(m.start())
    
    positions.sort()
    
    for i, start in enumerate(positions):
        end = positions[i + 1] if i + 1 < len(positions) else len(text)
        raw = text[start:end]
        cleaned = raw.replace('\n', '').replace('\r', '').replace(' ', '')
        if len(cleaned) > 30:
            nodes.append(cleaned)
    
    return list(dict.fromkeys(nodes))

def fetch_telegram():
    url = f"https://t.me/s/{CHANNEL}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://t.me/",
        "Cache-Control": "no-cache",
    }
    
    r = requests.get(url, headers
