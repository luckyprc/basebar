#!/usr/bin/env python3
import re
import urllib.request
from datetime import datetime, timezone

CHANNEL = "Outline_Vpn"
KV_FILE = "sub.txt"
PROTOCOLS = ['vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'hysteria2://', 'hy2://', 'tuic://', 'wg://']

def log(msg):
    print(f"[{datetime.now().isoformat()}] {msg}")

def clean_html(raw):
    text = raw.replace('<br>', '\n').replace('<br/>', '\n').replace('<br />', '\n')
    text = re.sub(r'<[^>]+>', '', text)
    for old, new in [('&nbsp;', ' '), ('&lt;', '<'), ('&gt;', '>'), ('&amp;', '&'), ('&#39;', "'"), ('&quot;', '"')]:
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
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://t.me/",
        "Cache-Control": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=15) as resp:
        html = resp.read().decode('utf-8')

    log(f"HTML: {len(html)} bytes")

    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    log(f"Today (UTC): {today}")

    dates = []
    for m in re.finditer(r'<a class="tgme_widget_message_date[^"]*"[^>]*><time datetime="([^"]+)"', html):
        dates.append(m.group(1)[:10])

    texts = []
    for m in re.finditer(r'<div class="tgme_widget_message_text[^"]*"[^>]*>([\s\S]*?)</div>', html):
        texts.append(clean_html(m.group(1)))

    log(f"Messages: {len(dates)} dates, {len(texts)} texts")

    count = min(len(dates), len(texts))
    all_nodes = []

    for i in range(count):
        nodes = extract_nodes(texts[i])
        if nodes:
            log(f"Msg {i} [{dates[i]}]: {len(nodes)} nodes")
        if dates[i] == today:
            all_nodes.extend(nodes)

    if not all_nodes and dates:
        latest = max(set(dates))
        log(f"No nodes for today, fallback to {latest}")
        for i in range(count):
            if dates[i] == latest:
                all_nodes.extend(extract_nodes(texts[i]))

    return list(dict.fromkeys(all_nodes))

def main():
    log("=== Start Fetch ===")
    nodes = fetch_telegram()
    if not nodes:
        log("No nodes found")
        with open(KV_FILE, "w", encoding="utf-8") as f:
            f.write("")
        return
    content = '\n'.join(nodes)
    with open(KV_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    log(f"SUCCESS: {len(nodes)} nodes -> {KV_FILE}")

if __name__ == "__main__":
    main()
