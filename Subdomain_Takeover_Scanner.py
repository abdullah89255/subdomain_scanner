#!/usr/bin/env python3
"""
Fast Subdomain Takeover Scanner
"""

import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import sys

async def check_takeover_fast(session, domain):
    takeover_strings = [
        ("GitHub", "There isn't a GitHub Pages site here"),
        ("AWS S3", "NoSuchBucket"),
        ("Heroku", "No such app"),
        ("GitLab", "Project Not Found"),
    ]
    
    try:
        async with session.get(f"http://{domain}", timeout=5) as resp:
            text = await resp.text()
            for service, pattern in takeover_strings:
                if pattern in text:
                    return domain, service, "VULNERABLE"
    except:
        pass
    
    return domain, None, "OK"

async def fast_scanner(subdomains_file):
    with open(subdomains_file) as f:
        domains = [line.strip() for line in f if line.strip()]
    
    connector = aiohttp.TCPConnector(limit=100)
    timeout = aiohttp.ClientTimeout(total=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [check_takeover_fast(session, domain) for domain in domains]
        results = await asyncio.gather(*tasks)
    
    # Print vulnerable domains
    for domain, service, status in results:
        if status == "VULNERABLE":
            print(f"[!] {domain} - {service} takeover possible")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 fast_scanner.py all_subs.txt")
        sys.exit(1)
    
    asyncio.run(fast_scanner(sys.argv[1]))
