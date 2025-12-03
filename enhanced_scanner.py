#!/usr/bin/env python3
"""
Enterprise Subdomain Vulnerability Scanner
Enhanced with Port Scanning, SSL Analysis, Content Discovery, Screenshots, and Email Alerts
Author: Security Assessment Tool
"""

import asyncio
import aiohttp
import socket
import ssl
import dns.resolver
import json
import os
import sys
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from typing import List, Dict, Any, Optional
import base64
import hashlib

# Try to import optional dependencies
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Common wordlists for content discovery
COMMON_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/admin.php", "/admin/login",
    "/dashboard", "/manager", "/control", "/cp", "/cpanel", "/webadmin",
    "/.env", "/config.php", "/wp-config.php", "/config.json", "/settings.py",
    "/.git/config", "/.svn/entries", "/.htaccess", "/web.config",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/database.sql",
    "/dump.sql", "/backup.tar", "/backup.rar",
    "/phpinfo.php", "/test.php", "/info.php", "/server-status",
    "/.git/", "/.svn/", "/.hg/", "/.DS_Store",
    "/api", "/api/v1", "/api/v2", "/graphql", "/rest", "/soap",
    "/readme.md", "/README", "/CHANGELOG", "/LICENSE",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/security.txt"
]

# Common ports to scan
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000,
    11211, 27017
]

# HTML Report Template
HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .header { 
            background: linear-gradient(135deg, #1a237e 0%, #4a148c 100%);
            color: white; 
            padding: 40px; 
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
        }
        .summary-cards { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); 
            gap: 20px; 
            padding: 30px;
            background: #f8f9fa;
        }
        .card { 
            background: white; 
            padding: 25px; 
            border-radius: 10px; 
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
            text-align: center;
        }
        .card.critical { border-top: 5px solid #dc3545; }
        .card.high { border-top: 5px solid #fd7e14; }
        .card.medium { border-top: 5px solid #ffc107; }
        .card.low { border-top: 5px solid #28a745; }
        .severity-badge { 
            display: inline-block; 
            padding: 4px 12px; 
            border-radius: 20px; 
            color: white; 
            font-size: 12px; 
            font-weight: bold;
            margin-right: 8px;
            margin-bottom: 8px;
        }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: black; }
        .severity-low { background: #28a745; }
        .filter-buttons { 
            padding: 20px 30px; 
            background: white;
            border-bottom: 1px solid #eee;
        }
        .filter-btn { 
            padding: 10px 20px; 
            margin-right: 10px; 
            border: none; 
            border-radius: 25px; 
            cursor: pointer; 
            background: #6c757d; 
            color: white;
            font-weight: bold;
        }
        .filter-btn.active { background: #667eea; }
        .results-container { padding: 0 30px 30px; }
        .domain-result { 
            background: white; 
            margin-bottom: 25px; 
            border-radius: 15px; 
            overflow: hidden; 
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
        }
        .domain-header { 
            background: #f8f9fa; 
            padding: 20px 25px; 
            border-bottom: 1px solid #e9ecef; 
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .domain-title {
            display: flex;
            align-items: center;
            gap: 15px;
            font-size: 1.2em;
            font-weight: 600;
        }
        .domain-content { padding: 25px; display: none; }
        .domain-content.active { display: block; }
        .section { margin-bottom: 25px; padding: 20px; background: #f8f9fa; border-radius: 10px; }
        .port-list { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }
        .port { background: #667eea; color: white; padding: 5px 15px; border-radius: 20px; font-size: 12px; }
        .vuln-item { padding: 15px; margin: 10px 0; background: white; border-radius: 8px; border-left: 4px solid; }
        .vuln-critical { border-left-color: #dc3545; }
        .screenshot { max-width: 100%; max-height: 400px; border: 1px solid #ddd; margin: 10px 0; }
        .ssl-grade { font-size: 2em; font-weight: bold; padding: 10px 20px; border-radius: 10px; display: inline-block; }
        .grade-a { background: #28a745; color: white; }
        .grade-f { background: #dc3545; color: white; }
        .timestamp { color: #6c757d; font-size: 0.9em; margin-top: 10px; }
        pre { background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <p>Generated on {{timestamp}} | Total: {{total_domains}} domains</p>
        </div>
        
        <div class="summary-cards">
            <div class="card critical"><h3>{{critical_count}}</h3><p>Critical</p></div>
            <div class="card high"><h3>{{high_count}}</h3><p>High</p></div>
            <div class="card medium"><h3>{{medium_count}}</h3><p>Medium</p></div>
            <div class="card low"><h3>{{low_count}}</h3><p>Low</p></div>
        </div>
        
        <div class="filter-buttons">
            <button class="filter-btn active" onclick="filterResults('all')">All</button>
            <button class="filter-btn" onclick="filterResults('critical')">Critical</button>
            <button class="filter-btn" onclick="filterResults('vulnerable')">Vulnerable</button>
        </div>
        
        <div class="results-container">
            {% if results %}
                {% for result in results %}
                <div class="domain-result" data-severity="{{result.severity}}" data-vulnerable="{{'true' if result.vulnerabilities else 'false'}}">
                    <div class="domain-header" onclick="toggleDomain('{{result.domain|replace('.', '_')}}')">
                        <div class="domain-title">
                            <span>{{result.domain}}</span>
                            <span class="severity-badge severity-{{result.severity}}">{{result.severity|upper}}</span>
                        </div>
                        <div>▼</div>
                    </div>
                    
                    <div class="domain-content" id="content-{{result.domain|replace('.', '_')}}">
                        {% if result.port_scan and result.port_scan.open_ports %}
                        <div class="section">
                            <h3>🔍 Open Ports ({{result.port_scan.open_ports|length}})</h3>
                            <div class="port-list">
                                {% for port in result.port_scan.open_ports %}
                                <span class="port">{{port}}</span>
                                {% endfor %}
                            </div>
                        </div>
                        {% endif %}
                        
                        {% if result.vulnerabilities %}
                        <div class="section">
                            <h3>🚨 Vulnerabilities ({{result.vulnerabilities|length}})</h3>
                            {% for vuln in result.vulnerabilities %}
                            <div class="vuln-item vuln-{{vuln.severity}}">
                                <strong>{{vuln.title}}</strong> <span class="severity-badge severity-{{vuln.severity}}">{{vuln.severity|upper}}</span>
                                <p>{{vuln.description}}</p>
                            </div>
                            {% endfor %}
                        </div>
                        {% endif %}
                        
                        <div class="timestamp">Scanned: {{result.timestamp}}</div>
                    </div>
                </div>
                {% endfor %}
            {% endif %}
        </div>
    </div>
    
    <script>
        function toggleDomain(domainId) {
            const content = document.getElementById('content-' + domainId);
            content.classList.toggle('active');
        }
        
        function filterResults(filter) {
            const domains = document.querySelectorAll('.domain-result');
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            domains.forEach(domain => {
                const severity = domain.getAttribute('data-severity');
                const isVulnerable = domain.getAttribute('data-vulnerable') === 'true';
                
                let show = false;
                switch(filter) {
                    case 'all': show = true; break;
                    case 'critical': show = severity === 'critical'; break;
                    case 'vulnerable': show = isVulnerable; break;
                }
                domain.style.display = show ? 'block' : 'none';
            });
        }
    </script>
</body>
</html>"""

class EnhancedSubdomainScanner:
    def __init__(self, input_file: str, output_dir: str = "scan_results",
                 max_workers: int = 50, timeout: int = 10,
                 email_config: Optional[Dict] = None):
        self.input_file = input_file
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.timeout = timeout
        self.email_config = email_config
        
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "screenshots"), exist_ok=True)
        
        self.results = []
        self.critical_findings = []
        self.vulnerability_count = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        }
        
        self.playwright = None
        self.browser = None
        self.takeover_patterns = [
            (r"404 Not Found", "Generic"),
            (r"NoSuchBucket", "AWS S3"),
            (r"GitHub Pages", "GitHub"),
            (r"Project Not Found", "GitLab"),
        ]

    async def init_resources(self):
        """Initialize async resources"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=self.max_workers, ssl=False)
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        
        if PLAYWRIGHT_AVAILABLE:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=True)
    
    async def close_resources(self):
        """Close all resources"""
        if self.session:
            await self.session.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

    def load_subdomains(self) -> List[str]:
        """Load subdomains from input file"""
        try:
            with open(self.input_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(subdomains)} subdomains")
            return list(set(subdomains))
        except FileNotFoundError:
            print(f"[!] File {self.input_file} not found!")
            sys.exit(1)

    async def port_scan(self, domain: str) -> Dict[str, Any]:
        """Perform async port scanning"""
        open_ports = []
        
        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(domain, port),
                    timeout=2
                )
                writer.close()
                await writer.wait_closed()
                return port, True
            except:
                return port, False
        
        tasks = [check_port(port) for port in COMMON_PORTS[:20]]  # Check first 20 ports
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, tuple):
                port, is_open = result
                if is_open:
                    open_ports.append(port)
        
        return {'open_ports': open_ports}

    async def analyze_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Perform SSL certificate analysis"""
        result = {'valid': False, 'grade': 'F', 'issues': []}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result['valid'] = True
                    
                    tls_version = ssock.version()
                    if tls_version in ['SSLv2', 'SSLv3', 'TLSv1']:
                        result['grade'] = 'F'
                        result['issues'].append(f"Deprecated: {tls_version}")
                    elif tls_version == 'TLSv1.1':
                        result['grade'] = 'C'
                    else:
                        result['grade'] = 'A'
        
        except Exception as e:
            result['issues'].append(f"Error: {str(e)}")
        
        return result

    async def content_discovery(self, domain: str) -> Dict[str, Any]:
        """Brute-force directories and files"""
        result = {'found': []}
        
        async def check_path(path):
            try:
                async with self.session.head(f"http://{domain}{path}", timeout=5) as response:
                    if response.status < 400:
                        return path
            except:
                pass
            return None
        
        tasks = [check_path(path) for path in COMMON_PATHS[:30]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for res in results:
            if res:
                result['found'].append(res)
        
        return result

    async def capture_screenshot(self, domain: str) -> Optional[Dict[str, Any]]:
        """Capture screenshot of the website"""
        if not PLAYWRIGHT_AVAILABLE or not self.browser:
            return None
        
        try:
            page = await self.browser.new_page(viewport={'width': 1920, 'height': 1080})
            
            for protocol in ['https', 'http']:
                url = f"{protocol}://{domain}"
                try:
                    await page.goto(url, timeout=10000)
                    break
                except:
                    continue
            
            screenshot_dir = os.path.join(self.output_dir, "screenshots")
            safe_domain = domain.replace('/', '_').replace(':', '_')
            screenshot_path = os.path.join(screenshot_dir, f"{safe_domain}.png")
            
            await page.screenshot(path=screenshot_path, full_page=True)
            title = await page.title()
            await page.close()
            
            return {
                'screenshot_path': screenshot_path,
                'title': title,
                'url': url
            }
        except Exception:
            return None

    async def check_subdomain_takeover(self, domain: str) -> Dict[str, Any]:
        """Check for subdomain takeover vulnerabilities"""
        result = {'vulnerable': False, 'service': None}
        
        try:
            for protocol in ['http', 'https']:
                url = f"{protocol}://{domain}"
                try:
                    async with self.session.get(url, timeout=10) as response:
                        text = await response.text()
                        
                        for pattern, service in self.takeover_patterns:
                            if re.search(pattern, text, re.IGNORECASE):
                                result['vulnerable'] = True
                                result['service'] = service
                                return result
                except:
                    continue
        except Exception:
            pass
        
        return result

    async def comprehensive_scan(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive scan of a single subdomain"""
        print(f"[*] Scanning {domain}")
        
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'port_scan': None,
            'ssl_analysis': None,
            'content_discovery': None,
            'takeover': None,
            'screenshot': None,
            'vulnerabilities': [],
            'severity': 'info',
            'risk_score': 0
        }
        
        try:
            # Port Scanning
            result['port_scan'] = await self.port_scan(domain)
            
            # SSL Analysis
            result['ssl_analysis'] = await self.analyze_ssl_certificate(domain)
            if result['ssl_analysis']['grade'] in ['D', 'F']:
                result['vulnerabilities'].append({
                    'title': 'SSL/TLS Issues',
                    'severity': 'high',
                    'description': f"SSL Grade: {result['ssl_analysis']['grade']}"
                })
            
            # Content Discovery
            result['content_discovery'] = await self.content_discovery(domain)
            if result['content_discovery']['found']:
                result['vulnerabilities'].append({
                    'title': 'Sensitive Files Found',
                    'severity': 'medium',
                    'description': f"Found {len(result['content_discovery']['found'])} interesting paths"
                })
            
            # Takeover Check
            result['takeover'] = await self.check_subdomain_takeover(domain)
            if result['takeover']['vulnerable']:
                result['vulnerabilities'].append({
                    'title': 'Subdomain Takeover',
                    'severity': 'critical',
                    'description': f"Potential {result['takeover']['service']} takeover"
                })
            
            # Screenshot
            result['screenshot'] = await self.capture_screenshot(domain)
            
            # Calculate risk
            for vuln in result['vulnerabilities']:
                if vuln['severity'] == 'critical':
                    result['risk_score'] += 10
                elif vuln['severity'] == 'high':
                    result['risk_score'] += 5
                elif vuln['severity'] == 'medium':
                    result['risk_score'] += 2
            
            # Determine severity
            if result['risk_score'] >= 10:
                result['severity'] = 'critical'
                self.critical_findings.append(result)
            elif result['risk_score'] >= 5:
                result['severity'] = 'high'
            elif result['risk_score'] >= 2:
                result['severity'] = 'medium'
            
            # Count vulnerabilities
            for vuln in result['vulnerabilities']:
                sev = vuln['severity']
                if sev in self.vulnerability_count:
                    self.vulnerability_count[sev] += 1
            
        except Exception as e:
            result['error'] = str(e)
        
        return result

    async def scan_batch(self, subdomains: List[str]):
        """Scan a batch of subdomains concurrently"""
        await self.init_resources()
        
        semaphore = asyncio.Semaphore(min(self.max_workers, 50))
        
        async def scan_with_limit(domain):
            async with semaphore:
                return await self.comprehensive_scan(domain)
        
        tasks = [scan_with_limit(domain) for domain in subdomains]
        
        chunk_size = 20
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
            
            for res in chunk_results:
                if isinstance(res, dict):
                    self.results.append(res)
            
            print(f"[+] Progress: {i + len(chunk)}/{len(subdomains)} domains")
            
            # Save progress
            if i % 100 == 0:
                self.save_progress()
        
        await self.close_resources()

    def save_progress(self):
        """Save scan progress"""
        progress_file = os.path.join(self.output_dir, "progress.json")
        with open(progress_file, 'w') as f:
            json.dump({
                'results': self.results,
                'vulnerability_count': self.vulnerability_count
            }, f, indent=2, default=str)

    def send_email_alert(self):
        """Send email alert for critical findings"""
        if not self.email_config or not self.critical_findings:
            return
        
        try:
            msg = MIMEMultipart('related')
            msg['Subject'] = f'Security Alert: {len(self.critical_findings)} Critical Findings'
            msg['From'] = self.email_config['from']
            msg['To'] = ', '.join(self.email_config['to'])
            
            html = f"""
            <html>
            <body>
                <h2>Security Scan Alert</h2>
                <p>Found {len(self.critical_findings)} critical vulnerabilities.</p>
                <p>Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr>
            """
            
            for finding in self.critical_findings[:5]:
                html += f"""
                <div style="border:1px solid #ddd; padding:15px; margin:10px 0;">
                    <div><strong>{finding['domain']}</strong></div>
                    <div>Risk Score: {finding.get('risk_score', 0)}</div>
                """
                
                for vuln in finding.get('vulnerabilities', []):
                    if vuln['severity'] in ['critical', 'high']:
                        html += f"<div>• {vuln['title']}</div>"
                
                html += "</div>"
            
            html += "</body></html>"
            
            msg.attach(MIMEText(html, 'html'))
            
            # Send email
            if self.email_config.get('use_ssl', True):
                server = smtplib.SMTP_SSL(self.email_config['smtp_server'], 
                                         self.email_config.get('smtp_port', 465))
            else:
                server = smtplib.SMTP(self.email_config['smtp_server'], 
                                     self.email_config.get('smtp_port', 587))
                server.starttls()
            
            server.login(self.email_config['username'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
            
            print(f"[+] Email alert sent")
            
        except Exception as e:
            print(f"[!] Failed to send email: {str(e)}")

    def generate_report(self):
        """Generate comprehensive HTML report"""
        try:
            from jinja2 import Template
        except ImportError:
            print("[!] Jinja2 not installed. Install with: pip install jinja2")
            self.generate_simple_html_report()
            return
        
        total_domains = len(self.results)
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerabilities'))
        
        # Calculate scan duration
        if self.results:
            timestamps = [datetime.fromisoformat(r['timestamp']) for r in self.results]
            min_time = min(timestamps)
            max_time = max(timestamps)
            duration = str(max_time - min_time).split('.')[0]
        else:
            duration = "0:00:00"
        
        template_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_domains': total_domains,
            'critical_count': self.vulnerability_count['critical'],
            'high_count': self.vulnerability_count['high'],
            'medium_count': self.vulnerability_count['medium'],
            'low_count': self.vulnerability_count['low'],
            'vulnerable_count': vulnerable_count,
            'duration': duration,
            'results': self.results,
            'results_json': json.dumps(self.results, default=str)
        }
        
        template = Template(HTML_TEMPLATE)
        html_content = template.render(**template_data)
        
        report_path = os.path.join(self.output_dir, "security_report.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report generated: {report_path}")
        
        # Also save JSON
        json_path = os.path.join(self.output_dir, "results.json")
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

    def generate_simple_html_report(self):
        """Generate simple HTML report without Jinja2"""
        report_path = os.path.join(self.output_dir, "security_report_simple.html")
        
        html = f"""<!DOCTYPE html>
<html>
<head><title>Security Scan Report</title></head>
<body>
    <h1>Security Scan Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Total Domains: {len(self.results)}</p>
    <p>Critical: {self.vulnerability_count['critical']}</p>
    <p>High: {self.vulnerability_count['high']}</p>
"""
        
        for result in self.results:
            if result.get('vulnerabilities'):
                html += f"""
    <div style="border:1px solid #ccc; margin:10px 0; padding:10px;">
        <h3>{result['domain']}</h3>
        <p>Risk Score: {result.get('risk_score', 0)}</p>
        <ul>
"""
                for vuln in result['vulnerabilities']:
                    html += f"<li>{vuln['title']} [{vuln['severity']}]</li>"
                html += "</ul></div>"
        
        html += "</body></html>"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"[+] Simple HTML report generated: {report_path}")

async def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Subdomain Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 enhanced_scanner.py -i subdomains.txt
  python3 enhanced_scanner.py -i subdomains.txt -o ./results -w 100
  python3 enhanced_scanner.py -i subdomains.txt --email config.json
        """
    )
    
    parser.add_argument("-i", "--input", required=True, help="Input file with subdomains")
    parser.add_argument("-o", "--output", default="scan_results", help="Output directory")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Timeout in seconds")
    parser.add_argument("--email", help="Email configuration JSON file")
    parser.add_argument("--skip-screenshots", action="store_true", help="Skip screenshot capture")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--limit", type=int, help="Limit number of subdomains to scan")
    
    args = parser.parse_args()
    
    # Load email configuration if provided
    email_config = None
    if args.email:
        try:
            with open(args.email, 'r') as f:
                email_config = json.load(f)
        except Exception as e:
            print(f"[!] Failed to load email config: {e}")
            return
    
    # Create scanner
    scanner = EnhancedSubdomainScanner(
        input_file=args.input,
        output_dir=args.output,
        max_workers=args.workers,
        timeout=args.timeout,
        email_config=email_config
    )
    
    # Load subdomains
    print("\n" + "="*60)
    print("ENTERPRISE SECURITY SCANNER")
    print("="*60)
    
    subdomains = scanner.load_subdomains()
    
    if args.limit:
        subdomains = subdomains[:args.limit]
        print(f"[+] Limiting scan to {args.limit} subdomains")
    
    # Start scanning
    print(f"\n[+] Starting scan of {len(subdomains)} subdomains")
    print(f"[+] Workers: {args.workers}, Timeout: {args.timeout}s")
    
    start_time = datetime.now()
    
    try:
        await scanner.scan_batch(subdomains)
        scanner.generate_report()
        
        if email_config and scanner.critical_findings:
            scanner.send_email_alert()
        
        elapsed = datetime.now() - start_time
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print(f"[+] Duration: {elapsed}")
        print(f"[+] Domains scanned: {len(scanner.results)}")
        print(f"[+] Critical findings: {len(scanner.critical_findings)}")
        print(f"[+] Reports saved to: {args.output}/")
        
        if scanner.critical_findings:
            print("\n🚨 CRITICAL FINDINGS:")
            for finding in scanner.critical_findings[:3]:
                print(f"  • {finding['domain']}: {finding.get('risk_score', 0)} risk")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
        scanner.save_progress()
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Check dependencies
    try:
        import aiohttp
        import dns.resolver
    except ImportError:
        print("[!] Install required packages: pip install aiohttp dnspython")
        sys.exit(1)
    
    asyncio.run(main())
