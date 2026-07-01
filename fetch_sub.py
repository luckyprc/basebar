#!/usr/bin/env python3
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

CHANNEL = "Outline_Vpn"
KV_FILE = "sub.txt"

NODE_PATTERNS = [
    r'vmess://[A-Za-z0-9+/=_\-]+',
    r'vless://[A-Za-z0-9+/=_\-@:]+',
    r'ss://[A-Za-z0-9+/=_\-@:]+',
    r'ssr://[A-Za-z0-9+/=_\-@:]+',
    r'trojan://[A-Za-z0-9+/=_\-@:]+',
    r'hysteria2?://[A-Za-z0-9+/=_\-@:]+',
    r'hy2://[A-Za-z0-9+/=_\-@:]+',
    r'tuic://[A-Za-z0-9+/=_\-@:]+',
    r'wg://[A-Za-z0-9+/=_\-@:]+',
]

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
    for pattern in NODE_PATTERNS:
        nodes.extend(re.findall(pattern, text))
    return list(dict.fromkeys(nodes))

def fetch_url(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://t.me/",
        "Cache-Control": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode('utf-8')

def fetch_telegram():
    url = f"https://t.me/s/{CHANNEL}"
    log(f"Fetching: {url}")
    
    html = fetch_url(url)
    log(f"HTML length: {len(html)}")
    
    if "tgme_channel_history" not in html and "tgme_widget_message" not in html:
        log("t.me/s/ returned contact/restricted page")
        return []
    
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    log(f"Today (UTC): {today}")
    
    # 提取日期
    dates = []
    for m in re.finditer(r'<a class="tgme_widget_message_date[^"]*"[^>]*><time datetime="([^"]+)"', html):
        dates.append(m.group(1)[:10])
    
    # 提取消息文本
    texts = []
    for m in re.finditer(r'<div class="tgme_widget_message_text[^"]*"[^>]*>([\s\S]*?)</div>', html):
        texts.append(clean_html(m.group(1)))
    
    log(f"Dates: {len(dates)}, Texts: {len(texts)}")
    
    count = min(len(dates), len(texts))
    all_nodes = []
    
    for i in range(count):
        if dates[i] == today:
            nodes = extract_nodes(texts[i])
            if nodes:
                log(f"Msg {i} ({dates[i]}): {len(nodes)} nodes")
                all_nodes.extend(nodes)
    
    return list(dict.fromkeys(all_nodes))

def main():
    log("=== Start Fetch ===")
    
    nodes = fetch_telegram()
    
    if not nodes:
        log("No nodes found for today")
        sys.exit(0)
    
    content = '\n'.join(nodes)
    
    with open(KV_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    
    log(f"SUCCESS: Saved {len(nodes)} nodes to {KV_FILE}")

if __name__ == "__main__":
    main()
