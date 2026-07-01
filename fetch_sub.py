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
    """提取完整节点链接（处理 Telegram 网页版换行截断）"""
    nodes = []
    positions = []
    
    # 找到所有协议头位置
    for proto in PROTOCOLS:
        for m in re.finditer(re.escape(proto), text):
            positions.append(m.start())
    
    positions.sort()
    
    # 从每个协议头提取到下一个协议头之前
    for i, start in enumerate(positions):
        end = positions[i + 1] if i + 1 < len(positions) else len(text)
        raw = text[start:end]
        # 去掉所有换行和空格（HTML 换行导致 URL 被拆分）
        cleaned = raw.replace('\n', '').replace('\r', '').replace(' ', '')
        # 过滤掉太短或不含 @ 的（不完整）
        if len(cleaned) > 30 and ('@' in cleaned or '?' in cleaned or '#' in cleaned):
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
    
    r = requests.get(url, headers=headers, timeout=15)
    log(f"t.me/s/ status: {r.status_code}, length: {len(r.text)}")
    
    if "tgme_channel_history" not in r.text and "tgme_widget_message" not in r.text:
        log("t.me/s/ returned contact/restricted page")
        return []
    
    html = r.text
    today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    log(f"Today (UTC): {today}")
    
    # 提取日期
    dates = []
    for m in re.finditer(r'<a class="tgme_widget_message_date[^"]*"[^>]*><time datetime="([^"]+)"', html):
        dates.append(m.group(1)[:10])
    
    # 提取消息文本（保留原始换行，方便跨行合并）
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
        # 创建空文件避免 git 报错
        with open(KV_FILE, "w", encoding="utf-8") as f:
            f.write("")
        sys.exit(0)
    
    content = '\n'.join(nodes)
    
    with open(KV_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    
    log(f"SUCCESS: Saved {len(nodes)} nodes to {KV_FILE}")

if __name__ == "__main__":
    main()
