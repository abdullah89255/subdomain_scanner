#!/usr/bin/env python3
"""
Comprehensive Subdomain Vulnerability Scanner
Author: Security Scanner Tool
"""

import asyncio
import aiohttp
import dns.resolver
import json
import ssl
import socket
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import argparse
import sys
from datetime import datetime
from typing import List, Dict, Any
import os

# HTML Report Template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomain Vulnerability Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: white; border-radius: 15px 15px 0 0; padding: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .header h1 { color: #333; margin-bottom: 10px; font-size: 2.5em; }
        .header .meta { color: #666; font-size: 0.9em; }
        .summary { background: white; padding: 25px; margin-top: 20px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .stat-card h3 { font-size: 2em; margin-bottom: 5px; }
        .stat-card p { opacity: 0.9; }
        .results { margin-top: 30px; }
        .domain-section { background: white; border-radius: 15px; margin-bottom: 25px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .domain-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; cursor: pointer; }
        .domain-header h2 { display: flex; justify-content: space-between; align-items: center; }
        .domain-content { padding: 0; max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }
        .domain-content.active { max-height: 5000px; padding: 25px; }
        .vuln-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .vuln-card { background: #f8f9fa; border-radius: 10px; padding: 20px; border-left: 5px solid #667eea; }
        .vuln-card.critical { border-left-color: #dc3545; }
        .vuln-card.high { border-left-color: #fd7e14; }
        .vuln-card.medium { border-left-color: #ffc107; }
        .vuln-card.low { border-left-color: #28a745; }
        .vuln-card.info { border-left-color: #17a2b8; }
        .vuln-card h4 { color: #333; margin-bottom: 10px; }
        .vuln-card p { color: #666; line-height: 1.6; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.8em; font-weight: bold; margin-right: 10px; }
        .badge.critical { background: #dc3545; color: white; }
        .badge.high { background: #fd7e14; color: white; }
        .badge.medium { background: #ffc107; color: black; }
        .badge.low { background: #28a745; color: white; }
        .badge.info { background: #17a2b8; color: white; }
        .severity { display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }
        .filter-buttons { margin: 20px 0; }
        .filter-btn { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; margin-right: 10px; cursor: pointer; transition: background 0.3s; }
        .filter-btn:hover { background: #5a67d8; }
        .filter-btn.active { background: #764ba2; }
        .status { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 10px; }
        .status.vulnerable { background: #dc3545; }
        .status.secure { background: #28a745; }
        .status.warning { background: #ffc107; }
        .status.info { background: #17a2b8; }
        pre { background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.9em; }
        .timestamp { color: #a0aec0; font-size: 0.9em; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏴‍☠️ Subdomain Vulnerability Report</h1>
            <p class="meta">Generated on {{timestamp}} | Total Subdomains Scanned: {{total_domains}}</p>
        </div>
        
        <div class="summary">
            <h3>📊 Executive Summary</h3>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{{critical_count}}</h3>
                    <p>Critical Issues</p>
                </div>
                <div class="stat-card">
                    <h3>{{high_count}}</h3>
                    <p>High Severity</p>
                </div>
                <div class="stat-card">
                    <h3>{{medium_count}}</h3>
                    <p>Medium Severity</p>
                </div>
                <div class="stat-card">
                    <h3>{{low_count}}</h3>
                    <p>Low Severity</p>
                </div>
            </div>
        </div>
        
        <div class="filter-buttons">
            <button class="filter-btn active" onclick="filterResults('all')">All ({{total_domains}})</button>
            <button class="filter-btn" onclick="filterResults('critical')">Critical ({{critical_count}})</button>
            <button class="filter-btn" onclick="filterResults('high')">High ({{high_count}})</button>
            <button class="filter-btn" onclick="filterResults('vulnerable')">Vulnerable ({{vulnerable_count}})</button>
        </div>
        
        <div class="results">
            {{results}}
        </div>
    </div>
    
    <script>
        function toggleDomain(domainId) {
            const content = document.getElementById('content-' + domainId);
            content.classList.toggle('active');
        }
        
        function filterResults(filter) {
            const domains = document.querySelectorAll('.domain-section');
            const buttons = document.querySelectorAll('.filter-btn');
            
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            domains.forEach(domain => {
                const severity = domain.getAttribute('data-severity');
                const isVulnerable = domain.getAttribute('data-vulnerable') === 'true';
                
                switch(filter) {
                    case 'all':
                        domain.style.display = 'block';
                        break;
                    case 'critical':
                        domain.style.display = severity === 'critical' ? 'block' : 'none';
                        break;
                    case 'high':
                        domain.style.display = severity === 'high' ? 'block' : 'none';
                        break;
                    case 'vulnerable':
                        domain.style.display = isVulnerable ? 'block' : 'none';
                        break;
                }
            });
        }
    </script>
</body>
</html>
"""

class SubdomainScanner:
    def __init__(self, input_file: str, output_file: str = "report.html", 
                 max_workers: int = 50, timeout: int = 10):
        self.input_file = input_file
        self.output_file = output_file
        self.max_workers = max_workers
        self.timeout = timeout
        self.results = []
        self.session = None
        self.vulnerability_count = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Known takeover strings for subdomain takeover detection
        self.takeover_strings = [
            "There isn't a GitHub Pages site here",
            "Project Not Found",
            "404 Not Found",
            "NoSuchBucket",
            "The specified bucket does not exist",
            "Repository not found",
            "The resource that you are attempting to access does not exist",
            "This site is currently unavailable",
            "The requested URL was not found on this server"
        ]
        
        # Sensitive files to check
        self.sensitive_files = [
            "/.git/HEAD",
            "/.env",
            "/config.php",
            "/wp-config.php",
            "/.htaccess",
            "/web.config",
            "/phpinfo.php",
            "/admin/config.php",
            "/backup.zip",
            "/database.sql",
            "/robots.txt",
            "/sitemap.xml"
        ]
        
        # Common admin panel paths
        self.admin_panels = [
            "/admin",
            "/admin/login",
            "/administrator",
            "/wp-admin",
            "/dashboard",
            "/manage",
            "/control",
            "/backend",
            "/cpanel",
            "/webadmin"
        ]
        
        # Technology signatures
        self.tech_signatures = {
            'wordpress': ['wp-content', 'wp-includes', 'WordPress'],
            'joomla': ['joomla', 'Joomla'],
            'drupal': ['Drupal', 'drupal.js'],
            'laravel': ['laravel', 'csrf-token'],
            'nginx': ['nginx', 'Server: nginx'],
            'apache': ['Apache', 'Server: Apache'],
            'iis': ['IIS', 'Microsoft-IIS'],
            'cloudflare': ['cloudflare', 'CF-Ray'],
            'aws': ['aws', 'Amazon', 'S3']
        }

    async def init_session(self):
        """Initialize async HTTP session"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)

    async def close_session(self):
        """Close async HTTP session"""
        if self.session:
            await self.session.close()

    def load_subdomains(self) -> List[str]:
        """Load subdomains from input file"""
        try:
            with open(self.input_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(subdomains)} subdomains from {self.input_file}")
            return subdomains
        except FileNotFoundError:
            print(f"[!] File {self.input_file} not found!")
            sys.exit(1)

    async def check_https_security(self, domain: str) -> Dict[str, Any]:
        """Check HTTPS/TLS security"""
        result = {
            'ssl_valid': False,
            'grade': 'F',
            'issues': []
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    result['ssl_valid'] = True
                    
                    # Check TLS version
                    tls_version = ssock.version()
                    if tls_version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.0']:
                        result['grade'] = 'D'
                        result['issues'].append(f"Deprecated TLS version: {tls_version}")
                    elif tls_version == 'TLSv1.1':
                        result['grade'] = 'C'
                        result['issues'].append(f"Outdated TLS version: {tls_version}")
                    else:
                        result['grade'] = 'A'
                    
                    # Check certificate expiration
                    from datetime import datetime
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_to_expire = (expiry_date - datetime.now()).days
                        if days_to_expire < 30:
                            result['grade'] = 'C'
                            result['issues'].append(f"Certificate expires in {days_to_expire} days")
        
        except Exception as e:
            result['issues'].append(f"SSL/TLS error: {str(e)}")
        
        return result

    async def check_security_headers(self, url: str) -> Dict[str, Any]:
        """Check security headers"""
        headers_to_check = {
            'Strict-Transport-Security': {'required': True, 'severity': 'high'},
            'Content-Security-Policy': {'required': True, 'severity': 'medium'},
            'X-Frame-Options': {'required': True, 'severity': 'medium'},
            'X-Content-Type-Options': {'required': True, 'severity': 'low'},
            'X-XSS-Protection': {'required': False, 'severity': 'low'},
            'Referrer-Policy': {'required': False, 'severity': 'low'},
        }
        
        result = {'missing': [], 'insecure': [], 'present': []}
        
        try:
            async with self.session.get(url, allow_redirects=True, ssl=False) as response:
                for header, config in headers_to_check.items():
                    if header in response.headers:
                        header_value = response.headers[header]
                        result['present'].append(f"{header}: {header_value}")
                        
                        # Additional checks for specific headers
                        if header == 'X-Frame-Options' and header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                            result['insecure'].append(f"Insecure {header}: {header_value}")
                    elif config['required']:
                        result['missing'].append(header)
        except Exception as e:
            result['missing'] = [f"Failed to check headers: {str(e)}"]
        
        return result

    async def check_cors_misconfiguration(self, url: str) -> Dict[str, Any]:
        """Check for CORS misconfigurations"""
        result = {'vulnerable': False, 'details': []}
        
        try:
            headers = {'Origin': 'https://evil.com'}
            async with self.session.get(url, headers=headers, allow_redirects=True) as response:
                acao_header = response.headers.get('Access-Control-Allow-Origin', '')
                acac_header = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao_header == '*':
                    result['vulnerable'] = True
                    result['details'].append("CORS allows all origins (*)")
                    if acac_header.lower() == 'true':
                        result['details'].append("Credentials allowed with wildcard origin - CRITICAL")
                
                elif 'evil.com' in acao_header:
                    result['vulnerable'] = True
                    result['details'].append("Reflects arbitrary origin")
                
                # Check for null origin
                headers = {'Origin': 'null'}
                async with self.session.get(url, headers=headers) as response:
                    if response.headers.get('Access-Control-Allow-Origin') == 'null':
                        result['vulnerable'] = True
                        result['details'].append("Allows null origin")
        
        except Exception as e:
            result['details'].append(f"Error checking CORS: {str(e)}")
        
        return result

    async def check_subdomain_takeover(self, domain: str) -> Dict[str, Any]:
        """Check for subdomain takeover vulnerabilities"""
        result = {'vulnerable': False, 'service': None, 'evidence': None}
        
        try:
            # Check HTTP
            http_url = f"http://{domain}"
            async with self.session.get(http_url, allow_redirects=True) as response:
                text = await response.text()
                
                for service, strings in [
                    ('GitHub Pages', ['There isn\'t a GitHub Pages site here']),
                    ('AWS S3', ['NoSuchBucket', 'The specified bucket does not exist']),
                    ('Heroku', ['No such app']),
                    ('GitLab', ['Project Not Found']),
                    ('Shopify', ['Sorry, this shop is currently unavailable']),
                ]:
                    for string in strings:
                        if string in text:
                            result['vulnerable'] = True
                            result['service'] = service
                            result['evidence'] = string
                            return result
            
            # Check HTTPS if HTTP failed
            https_url = f"https://{domain}"
            async with self.session.get(https_url, allow_redirects=True) as response:
                text = await response.text()
                
                for string in self.takeover_strings:
                    if string in text:
                        result['vulnerable'] = True
                        result['service'] = "Unknown"
                        result['evidence'] = string
                        return result
        
        except Exception:
            pass
        
        return result

    async def check_sensitive_files(self, domain: str) -> Dict[str, Any]:
        """Check for exposed sensitive files"""
        result = {'found': [], 'status_codes': {}}
        
        for file in self.sensitive_files[:5]:  # Check first 5 files for speed
            try:
                url = f"http://{domain}{file}"
                async with self.session.head(url, allow_redirects=False) as response:
                    if response.status in [200, 403]:
                        result['found'].append(file)
                        result['status_codes'][file] = response.status
            except Exception:
                continue
        
        return result

    async def check_admin_panels(self, domain: str) -> Dict[str, Any]:
        """Check for exposed admin panels"""
        result = {'found': [], 'status_codes': {}}
        
        for panel in self.admin_panels[:5]:  # Check first 5 panels
            try:
                url = f"http://{domain}{panel}"
                async with self.session.head(url, allow_redirects=False) as response:
                    if response.status in [200, 301, 302]:
                        result['found'].append(panel)
                        result['status_codes'][panel] = response.status
            except Exception:
                continue
        
        return result

    async def detect_technology(self, domain: str) -> Dict[str, Any]:
        """Detect technologies used"""
        result = {'technologies': [], 'headers': {}}
        
        try:
            url = f"http://{domain}"
            async with self.session.get(url, allow_redirects=True) as response:
                # Get response headers
                for header, value in response.headers.items():
                    result['headers'][header] = value
                
                # Get response text
                text = await response.text()
                
                # Check for technology signatures
                for tech, signatures in self.tech_signatures.items():
                    for sig in signatures:
                        if sig.lower() in text.lower() or any(sig.lower() in h.lower() for h in response.headers.values()):
                            if tech not in result['technologies']:
                                result['technologies'].append(tech)
        
        except Exception as e:
            result['technologies'].append(f"Error: {str(e)}")
        
        return result

    def perform_dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Perform DNS enumeration"""
        result = {
            'a_records': [],
            'cname_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': []
        }
        
        try:
            # A Records
            answers = dns.resolver.resolve(domain, 'A')
            result['a_records'] = [str(r) for r in answers]
        except:
            pass
        
        try:
            # CNAME Records
            answers = dns.resolver.resolve(domain, 'CNAME')
            result['cname_records'] = [str(r) for r in answers]
        except:
            pass
        
        try:
            # MX Records
            answers = dns.resolver.resolve(domain, 'MX')
            result['mx_records'] = [str(r) for r in answers]
        except:
            pass
        
        try:
            # TXT Records
            answers = dns.resolver.resolve(domain, 'TXT')
            result['txt_records'] = [str(r) for r in answers]
        except:
            pass
        
        try:
            # NS Records
            answers = dns.resolver.resolve(domain, 'NS')
            result['ns_records'] = [str(r) for r in answers]
        except:
            pass
        
        return result

    async def scan_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Perform all checks on a single subdomain"""
        print(f"[*] Scanning {subdomain}")
        
        result = {
            'domain': subdomain,
            'timestamp': datetime.now().isoformat(),
            'takeover': None,
            'https_security': None,
            'security_headers': None,
            'cors': None,
            'sensitive_files': None,
            'admin_panels': None,
            'technology': None,
            'dns': None,
            'overall_severity': 'info',
            'vulnerable': False,
            'issues': []
        }
        
        try:
            # Check subdomain takeover
            result['takeover'] = await self.check_subdomain_takeover(subdomain)
            if result['takeover']['vulnerable']:
                result['issues'].append({
                    'title': 'Subdomain Takeover',
                    'severity': 'critical',
                    'details': f"Vulnerable to {result['takeover']['service']} takeover",
                    'evidence': result['takeover']['evidence']
                })
                result['vulnerable'] = True
                result['overall_severity'] = 'critical'
            
            # Check HTTPS security
            result['https_security'] = await self.check_https_security(subdomain)
            if result['https_security']['grade'] in ['D', 'F']:
                severity = 'high' if result['https_security']['grade'] == 'F' else 'medium'
                result['issues'].append({
                    'title': 'HTTPS Security Issues',
                    'severity': severity,
                    'details': f"TLS Grade: {result['https_security']['grade']}",
                    'evidence': ', '.join(result['https_security']['issues'][:3])
                })
                if result['overall_severity'] == 'info':
                    result['overall_severity'] = severity
                result['vulnerable'] = True
            
            # Check security headers
            result['security_headers'] = await self.check_security_headers(f"https://{subdomain}")
            if result['security_headers']['missing']:
                result['issues'].append({
                    'title': 'Missing Security Headers',
                    'severity': 'medium',
                    'details': f"Missing: {', '.join(result['security_headers']['missing'][:3])}",
                    'evidence': str(result['security_headers']['missing'])
                })
                if result['overall_severity'] == 'info':
                    result['overall_severity'] = 'medium'
                result['vulnerable'] = True
            
            # Check CORS
            result['cors'] = await self.check_cors_misconfiguration(f"https://{subdomain}")
            if result['cors']['vulnerable']:
                result['issues'].append({
                    'title': 'CORS Misconfiguration',
                    'severity': 'medium',
                    'details': 'CORS policy allows unauthorized domains',
                    'evidence': ', '.join(result['cors']['details'])
                })
                if result['overall_severity'] == 'info':
                    result['overall_severity'] = 'medium'
                result['vulnerable'] = True
            
            # Check sensitive files
            result['sensitive_files'] = await self.check_sensitive_files(subdomain)
            if result['sensitive_files']['found']:
                result['issues'].append({
                    'title': 'Sensitive Files Exposed',
                    'severity': 'high',
                    'details': f"Found {len(result['sensitive_files']['found'])} sensitive files",
                    'evidence': ', '.join(result['sensitive_files']['found'][:3])
                })
                if result['overall_severity'] in ['info', 'medium']:
                    result['overall_severity'] = 'high'
                result['vulnerable'] = True
            
            # Check admin panels
            result['admin_panels'] = await self.check_admin_panels(subdomain)
            if result['admin_panels']['found']:
                result['issues'].append({
                    'title': 'Admin Panels Exposed',
                    'severity': 'medium',
                    'details': f"Found {len(result['admin_panels']['found'])} admin panels",
                    'evidence': ', '.join(result['admin_panels']['found'][:3])
                })
                if result['overall_severity'] == 'info':
                    result['overall_severity'] = 'medium'
                result['vulnerable'] = True
            
            # Detect technology
            result['technology'] = await self.detect_technology(subdomain)
            
            # DNS enumeration
            result['dns'] = self.perform_dns_enumeration(subdomain)
            
            # Count vulnerabilities
            for issue in result['issues']:
                severity = issue['severity']
                if severity in self.vulnerability_count:
                    self.vulnerability_count[severity] += 1
            
        except Exception as e:
            result['error'] = str(e)
            print(f"[!] Error scanning {subdomain}: {str(e)}")
        
        return result

    async def scan_all(self, subdomains: List[str]):
        """Scan all subdomains concurrently"""
        await self.init_session()
        
        # Use semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def scan_with_semaphore(subdomain):
            async with semaphore:
                return await self.scan_subdomain(subdomain)
        
        # Create tasks for all subdomains
        tasks = [scan_with_semaphore(subdomain) for subdomain in subdomains]
        
        # Process in batches
        batch_size = 50
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            # Filter out exceptions
            for res in batch_results:
                if isinstance(res, dict):
                    self.results.append(res)
            
            print(f"[+] Processed {i + len(batch)}/{len(subdomains)} subdomains")
        
        await self.close_session()

    def generate_html_report(self):
        """Generate HTML report from scan results"""
        print(f"[+] Generating HTML report: {self.output_file}")
        
        # Sort results by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_results = sorted(self.results, 
                              key=lambda x: severity_order.get(x['overall_severity'], 5))
        
        # Generate results HTML
        results_html = ""
        for i, result in enumerate(sorted_results):
            domain_id = result['domain'].replace('.', '_')
            
            # Generate vulnerabilities HTML
            vuln_html = ""
            for issue in result.get('issues', []):
                vuln_html += f"""
                <div class="vuln-card {issue['severity']}">
                    <span class="badge {issue['severity']}">{issue['severity'].upper()}</span>
                    <h4>{issue['title']}</h4>
                    <p>{issue['details']}</p>
                    <pre>{issue.get('evidence', 'No evidence')}</pre>
                </div>
                """
            
            if not vuln_html:
                vuln_html = "<div class='vuln-card info'><h4>✅ No vulnerabilities found</h4><p>This subdomain appears to be secure</p></div>"
            
            # Status indicator
            status_class = 'vulnerable' if result.get('vulnerable') else 'secure'
            if result.get('issues'):
                if any(i['severity'] == 'critical' for i in result['issues']):
                    status_class = 'vulnerable'
                elif any(i['severity'] == 'high' for i in result['issues']):
                    status_class = 'warning'
            
            results_html += f"""
            <div class="domain-section" data-severity="{result['overall_severity']}" data-vulnerable="{str(result.get('vulnerable', False)).lower()}">
                <div class="domain-header" onclick="toggleDomain('{domain_id}')">
                    <h2>
                        <span>
                            <span class="status {status_class}"></span>
                            {result['domain']}
                        </span>
                        <span class="badge {result['overall_severity']}">
                            {result['overall_severity'].upper()}
                        </span>
                    </h2>
                </div>
                <div class="domain-content" id="content-{domain_id}">
                    <div class="vuln-grid">
                        {vuln_html}
                    </div>
                    <div style="margin-top: 20px;">
                        <h4>Technology Detected:</h4>
                        <p>{', '.join(result.get('technology', {}).get('technologies', ['Unknown']))}</p>
                        
                        <h4 style="margin-top: 15px;">DNS Records:</h4>
                        <pre>A: {', '.join(result.get('dns', {}).get('a_records', ['None']))}
CNAME: {', '.join(result.get('dns', {}).get('cname_records', ['None']))}
MX: {', '.join(result.get('dns', {}).get('mx_records', ['None']))}</pre>
                    </div>
                    <div class="timestamp">Scanned: {result['timestamp']}</div>
                </div>
            </div>
            """
        
        # Count vulnerable domains
        vulnerable_count = sum(1 for r in self.results if r.get('vulnerable', False))
        
        # Replace template variables
        html_content = HTML_TEMPLATE
        replacements = {
            '{{timestamp}}': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            '{{total_domains}}': str(len(self.results)),
            '{{critical_count}}': str(self.vulnerability_count['critical']),
            '{{high_count}}': str(self.vulnerability_count['high']),
            '{{medium_count}}': str(self.vulnerability_count['medium']),
            '{{low_count}}': str(self.vulnerability_count['low']),
            '{{vulnerable_count}}': str(vulnerable_count),
            '{{results}}': results_html
        }
        
        for placeholder, value in replacements.items():
            html_content = html_content.replace(placeholder, value)
        
        # Write HTML file
        with open(self.output_file, 'w') as f:
            f.write(html_content)
        
        print(f"[+] Report saved to {self.output_file}")

    def save_json_report(self, filename: str = "report.json"):
        """Save raw results as JSON"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"[+] JSON report saved to {filename}")

async def main():
    parser = argparse.ArgumentParser(description="Subdomain Vulnerability Scanner")
    parser.add_argument("-i", "--input", required=True, help="Input file containing subdomains")
    parser.add_argument("-o", "--output", default="report.html", help="Output HTML report file")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Maximum concurrent workers")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-j", "--json", help="Save JSON report")
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not os.path.exists(args.input):
        print(f"[!] Input file {args.input} not found!")
        sys.exit(1)
    
    scanner = SubdomainScanner(
        input_file=args.input,
        output_file=args.output,
        max_workers=args.workers,
        timeout=args.timeout
    )
    
    # Load subdomains
    subdomains = scanner.load_subdomains()
    
    # Start scanning
    print(f"[+] Starting scan with {args.workers} workers")
    start_time = datetime.now()
    
    await scanner.scan_all(subdomains[:100])  # Limit to first 100 for testing
    
    # Generate reports
    scanner.generate_html_report()
    
    if args.json:
        scanner.save_json_report(args.json)
    
    # Print summary
    elapsed = datetime.now() - start_time
    print(f"\n[+] Scan completed in {elapsed}")
    print(f"[+] Total subdomains scanned: {len(scanner.results)}")
    print(f"[+] Vulnerable subdomains: {sum(1 for r in scanner.results if r.get('vulnerable', False))}")
    print(f"[+] Critical issues: {scanner.vulnerability_count['critical']}")
    print(f"[+] High severity: {scanner.vulnerability_count['high']}")
    print(f"[+] Medium severity: {scanner.vulnerability_count['medium']}")

if __name__ == "__main__":
    asyncio.run(main())
