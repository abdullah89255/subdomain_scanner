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

# HTML Report Template (complete and properly terminated)
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
        .header p {
            opacity: 0.9;
            margin-top: 5px;
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
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        .card.critical { border-top: 5px solid #dc3545; }
        .card.high { border-top: 5px solid #fd7e14; }
        .card.medium { border-top: 5px solid #ffc107; }
        .card.low { border-top: 5px solid #28a745; }
        .card.info { border-top: 5px solid #17a2b8; }
        .card h3 {
            font-size: 2.5em;
            margin-bottom: 10px;
            color: #333;
        }
        .card p {
            color: #666;
            font-size: 0.9em;
        }
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
        .severity-critical { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }
        .severity-high { background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%); }
        .severity-medium { background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%); color: black; }
        .severity-low { background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%); }
        .severity-info { background: linear-gradient(135deg, #17a2b8 0%, #138496 100%); }
        
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
            transition: all 0.3s;
        }
        .filter-btn:hover { 
            background: #5a6268; 
            transform: scale(1.05);
        }
        .filter-btn.active { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        
        .results-container {
            padding: 0 30px 30px;
        }
        
        .domain-result { 
            background: white; 
            margin-bottom: 25px; 
            border-radius: 15px; 
            overflow: hidden; 
            box-shadow: 0 5px 20px rgba(0,0,0,0.08);
            border: 1px solid #e9ecef;
            transition: all 0.3s;
        }
        .domain-result:hover {
            box-shadow: 0 10px 30px rgba(0,0,0,0.15);
            border-color: #667eea;
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
        .domain-header:hover {
            background: #e9ecef;
        }
        .domain-title {
            display: flex;
            align-items: center;
            gap: 15px;
            font-size: 1.2em;
            font-weight: 600;
            color: #333;
        }
        .domain-status {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        .status-critical { background: #dc3545; box-shadow: 0 0 10px #dc3545; }
        .status-high { background: #fd7e14; box-shadow: 0 0 10px #fd7e14; }
        .status-medium { background: #ffc107; box-shadow: 0 0 10px #ffc107; }
        .status-low { background: #28a745; box-shadow: 0 0 10px #28a745; }
        .status-info { background: #17a2b8; box-shadow: 0 0 10px #17a2b8; }
        
        .domain-content { 
            padding: 25px; 
            display: none;
        }
        .domain-content.active {
            display: block;
            animation: slideDown 0.5s ease-out;
        }
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .section {
            margin-bottom: 25px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        .section h3 {
            margin-bottom: 15px;
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .port-list { 
            display: flex; 
            flex-wrap: wrap; 
            gap: 8px; 
            margin: 10px 0; 
        }
        .port { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white;
            padding: 5px 15px; 
            border-radius: 20px; 
            font-size: 12px; 
            font-weight: bold;
        }
        .port.common { background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%); }
        .port.danger { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }
        
        .vuln-item { 
            padding: 15px; 
            margin: 10px 0; 
            background: white;
            border-radius: 8px;
            border-left: 4px solid;
            box-shadow: 0 3px 10px rgba(0,0,0,0.08);
        }
        .vuln-critical { border-left-color: #dc3545; }
        .vuln-high { border-left-color: #fd7e14; }
        .vuln-medium { border-left-color: #ffc107; }
        .vuln-low { border-left-color: #28a745; }
        
        .screenshot-container {
            text-align: center;
            margin: 20px 0;
            padding: 20px;
            background: white;
            border-radius: 10px;
            border: 1px solid #dee2e6;
        }
        .screenshot { 
            max-width: 100%; 
            max-height: 400px;
            border: 1px solid #ddd; 
            margin: 10px 0; 
            border-radius: 5px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .ssl-grade {
            font-size: 2em;
            font-weight: bold;
            padding: 10px 20px;
            border-radius: 10px;
            display: inline-block;
            margin: 10px 0;
        }
        .grade-a { background: #28a745; color: white; }
        .grade-b { background: #17a2b8; color: white; }
        .grade-c { background: #ffc107; color: black; }
        .grade-d { background: #fd7e14; color: white; }
        .grade-f { background: #dc3545; color: white; }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .info-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #dee2e6;
        }
        
        .export-buttons {
            position: fixed;
            bottom: 30px;
            right: 30px;
            display: flex;
            gap: 10px;
        }
        .export-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-weight: bold;
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .export-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.6);
        }
        
        .no-results {
            text-align: center;
            padding: 50px;
            color: #6c757d;
            font-size: 1.2em;
        }
        
        .timestamp {
            color: #6c757d;
            font-size: 0.9em;
            margin-top: 10px;
            font-style: italic;
        }
        
        .risk-score {
            font-size: 1.5em;
            font-weight: bold;
            color: white;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 8px 20px;
            border-radius: 20px;
            display: inline-block;
        }
        
        pre {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }
        
        .toggle-icon {
            transition: transform 0.3s;
        }
        .rotated {
            transform: rotate(180deg);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Enterprise Security Scan Report</h1>
            <p>Comprehensive vulnerability assessment of {{total_domains}} subdomains</p>
            <p>Generated on {{timestamp}} | Scan Duration: {{duration}}</p>
        </div>
        
        <div class="summary-cards">
            <div class="card critical">
                <h3>{{critical_count}}</h3>
                <p>Critical Severity Issues</p>
                <div class="risk-score">{{critical_count * 10}} Risk Points</div>
            </div>
            <div class="card high">
                <h3>{{high_count}}</h3>
                <p>High Severity Issues</p>
                <div class="risk-score">{{high_count * 5}} Risk Points</div>
            </div>
            <div class="card medium">
                <h3>{{medium_count}}</h3>
                <p>Medium Severity Issues</p>
                <div class="risk-score">{{medium_count * 2}} Risk Points</div>
            </div>
            <div class="card low">
                <h3>{{low_count}}</h3>
                <p>Low Severity Issues</p>
                <div class="risk-score">{{low_count * 1}} Risk Points</div>
            </div>
        </div>
        
        <div class="filter-buttons">
            <button class="filter-btn active" onclick="filterResults('all')">All ({{total_domains}})</button>
            <button class="filter-btn" onclick="filterResults('critical')">Critical ({{critical_count}})</button>
            <button class="filter-btn" onclick="filterResults('high')">High ({{high_count}})</button>
            <button class="filter-btn" onclick="filterResults('vulnerable')">Vulnerable ({{vulnerable_count}})</button>
            <button class="filter-btn" onclick="filterResults('ports')">Open Ports</button>
            <button class="filter-btn" onclick="filterResults('takeover')">Takeover Risks</button>
        </div>
        
        <div class="results-container">
            {% if results %}
                {% for result in results %}
                <div class="domain-result" data-severity="{{result.severity}}" 
                     data-vulnerable="{{'true' if result.vulnerabilities else 'false'}}"
                     data-has-ports="{{'true' if result.port_scan and result.port_scan.open_ports else 'false'}}"
                     data-has-takeover="{{'true' if result.takeover and result.takeover.vulnerable else 'false'}}">
                    <div class="domain-header" onclick="toggleDomain('{{result.domain|replace('.', '_')}}')">
                        <div class="domain-title">
                            <div class="domain-status status-{{result.severity}}"></div>
                            <span>{{result.domain}}</span>
                            <span class="severity-badge severity-{{result.severity}}">{{result.severity|upper}}</span>
                            <span class="risk-score">{{result.risk_score}} Risk</span>
                        </div>
                        <div class="toggle-icon">▼</div>
                    </div>
                    
                    <div class="domain-content" id="content-{{result.domain|replace('.', '_')}}">
                        <!-- Port Scan Results -->
                        {% if result.port_scan and result.port_scan.open_ports %}
                        <div class="section">
                            <h3>🔍 Open Ports ({{result.port_scan.open_ports|length}})</h3>
                            <div class="port-list">
                                {% for port in result.port_scan.open_ports %}
                                <span class="port {% if port in [80,443,8080,8443] %}common{% elif port in [21,22,23,25,3389] %}danger{% endif %}">
                                    {{port}} {% if port == 80 %}HTTP{% elif port == 443 %}HTTPS{% elif port == 22 %}SSH{% elif port == 21 %}FTP{% elif port == 23 %}Telnet{% elif port == 25 %}SMTP{% elif port == 3389 %}RDP{% endif %}
                                </span>
                                {% endfor %}
                            </div>
                        </div>
                        {% endif %}
                        
                        <!-- SSL Analysis -->
                        {% if result.ssl_analysis %}
                        <div class="section">
                            <h3>🔐 SSL/TLS Security</h3>
                            <div class="ssl-grade grade-{{result.ssl_analysis.grade|lower}}">
                                Grade: {{result.ssl_analysis.grade}}
                            </div>
                            {% if result.ssl_analysis.valid %}
                            <p>Certificate Valid: ✅ Yes</p>
                            {% if result.ssl_analysis.details.days_to_expire %}
                            <p>Expires in: {{result.ssl_analysis.details.days_to_expire}} days</p>
                            {% endif %}
                            {% if result.ssl_analysis.details.tls_version %}
                            <p>TLS Version: {{result.ssl_analysis.details.tls_version}}</p>
                            {% endif %}
                            {% endif %}
                            {% if result.ssl_analysis.issues %}
                            <div style="margin-top: 15px;">
                                <strong>Issues:</strong>
                                <ul style="margin-top: 10px; padding-left: 20px;">
                                    {% for issue in result.ssl_analysis.issues %}
                                    <li>{{issue}}</li>
                                    {% endfor %}
                                </ul>
                            </div>
                            {% endif %}
                        </div>
                        {% endif %}
                        
                        <!-- Vulnerabilities -->
                        {% if result.vulnerabilities %}
                        <div class="section">
                            <h3>🚨 Vulnerabilities Found ({{result.vulnerabilities|length}})</h3>
                            {% for vuln in result.vulnerabilities %}
                            <div class="vuln-item vuln-{{vuln.severity}}">
                                <strong>{{vuln.title}}</strong>
                                <span class="severity-badge severity-{{vuln.severity}}">{{vuln.severity|upper}}</span>
                                <p>{{vuln.description}}</p>
                                {% if vuln.get('confidence') %}
                                <p><em>Confidence: {{vuln.confidence}}</em></p>
                                {% endif %}
                                {% if vuln.get('evidence') %}
                                <pre>{{vuln.evidence[:500]}}{% if vuln.evidence|length > 500 %}...{% endif %}</pre>
                                {% endif %}
                            </div>
                            {% endfor %}
                        </div>
                        {% endif %}
                        
                        <!-- Content Discovery -->
                        {% if result.content_discovery and result.content_discovery.found %}
                        <div class="section">
                            <h3>📁 Content Discovery</h3>
                            <p>Found {{result.content_discovery.found|length}} interesting paths:</p>
                            <div class="port-list">
                                {% for path in result.content_discovery.found[:15] %}
                                <span class="port">{{path}}</span>
                                {% endfor %}
                                {% if result.content_discovery.found|length > 15 %}
                                <span class="port">+{{result.content_discovery.found|length - 15}} more</span>
                                {% endif %}
                            </div>
                        </div>
                        {% endif %}
                        
                        <!-- Screenshot -->
                        {% if result.screenshot %}
                        <div class="screenshot-container">
                            <h3>🖼️ Screenshot</h3>
                            <img src="file://{{result.screenshot.screenshot_path}}" 
                                 alt="Screenshot of {{result.domain}}" 
                                 class="screenshot"
                                 onerror="this.style.display='none'">
                            <p><strong>Title:</strong> {{result.screenshot.title|default('N/A', true)}}</p>
                            <p><strong>URL:</strong> {{result.screenshot.url}}</p>
                        </div>
                        {% endif %}
                        
                        <!-- DNS Information -->
                        <div class="section">
                            <h3>🌐 DNS Information</h3>
                            <div class="info-grid">
                                <div class="info-card">
                                    <h4>Resolved IPs</h4>
                                    <p>{{result.dns.a_records|join(', ') if result.dns and result.dns.a_records else 'Not resolved'}}</p>
                                </div>
                                <div class="info-card">
                                    <h4>CNAME Records</h4>
                                    <p>{{result.dns.cname_records|join(', ') if result.dns and result.dns.cname_records else 'None'}}</p>
                                </div>
                            </div>
                        </div>
                        
                        <div class="timestamp">
                            Scanned: {{result.timestamp}}
                        </div>
                    </div>
                </div>
                {% endfor %}
            {% else %}
                <div class="no-results">
                    <h3>No results to display</h3>
                    <p>The scan completed but found no data to show.</p>
                </div>
            {% endif %}
        </div>
    </div>
    
    <div class="export-buttons">
        <button class="export-btn" onclick="exportJSON()">💾 Export JSON</button>
        <button class="export-btn" onclick="printReport()">🖨️ Print Report</button>
        <button class="export-btn" onclick="exportCSV()">📊 Export CSV</button>
    </div>
    
    <script>
        function toggleDomain(domainId) {
            const content = document.getElementById('content-' + domainId);
            const toggleIcon = content.parentElement.querySelector('.toggle-icon');
            
            content.classList.toggle('active');
            toggleIcon.classList.toggle('rotated');
        }
        
        function filterResults(filter) {
            const domains = document.querySelectorAll('.domain-result');
            const buttons = document.querySelectorAll('.filter-btn');
            
            // Update active button
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            // Filter domains
            domains.forEach(domain => {
                const severity = domain.getAttribute('data-severity');
                const isVulnerable = domain.getAttribute('data-vulnerable') === 'true';
                const hasPorts = domain.getAttribute('data-has-ports') === 'true';
                const hasTakeover = domain.getAttribute('data-has-takeover') === 'true';
                
                let show = false;
                
                switch(filter) {
                    case 'all':
                        show = true;
                        break;
                    case 'critical':
                        show = severity === 'critical';
                        break;
                    case 'high':
                        show = severity === 'high';
                        break;
                    case 'vulnerable':
                        show = isVulnerable;
                        break;
                    case 'ports':
                        show = hasPorts;
                        break;
                    case 'takeover':
                        show = hasTakeover;
                        break;
                }
                
                domain.style.display = show ? 'block' : 'none';
            });
        }
        
        function exportJSON() {
            const data = {{results_json|safe}};
            const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security_scan_report_{{timestamp|replace(" ", "_")|replace(":", "-")}}.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        function exportCSV() {
            let csv = 'Domain,Severity,Risk Score,Open Ports,Vulnerabilities,SSL Grade\\n';
            
            document.querySelectorAll('.domain-result').forEach(domain => {
                const domainName = domain.querySelector('.domain-title span').textContent;
                const severity = domain.getAttribute('data-severity');
                const riskScore = domain.querySelector('.risk-score')?.textContent || '0';
                
                const ports = [];
                domain.querySelectorAll('.port').forEach(port => {
                    ports.push(port.textContent.split(' ')[0]);
                });
                
                const vulnCount = domain.querySelectorAll('.vuln-item').length;
                const sslGrade = domain.querySelector('.ssl-grade')?.textContent || 'N/A';
                
                csv += `"${domainName}","${severity}","${riskScore}","${ports.join(',')}","${vulnCount}","${sslGrade}"\\n`;
            });
            
            const blob = new Blob([csv], {type: 'text/csv'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'security_scan_report_{{timestamp|replace(" ", "_")|replace(":", "-")}}.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        function printReport() {
            window.print();
        }
        
        // Expand all critical findings by default
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.domain-result[data-severity="critical"] .domain-header').forEach(header => {
                header.click();
            });
        });
    </script>
</body>
</html>"""

# Continue with the rest of the class definition (keep all the methods from the previous code)
# Make sure to replace the generate_report method with this:

    def generate_report(self):
        """Generate comprehensive HTML report"""
        try:
            from jinja2 import Template
        except ImportError:
            print("[!] Jinja2 not installed. Install with: pip install jinja2")
            # Create simple HTML report without Jinja2
            self.generate_simple_html_report()
            return
        
        # Calculate statistics
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
        
        # Prepare template data
        template_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_domains': total_domains,
            'critical_count': self.vulnerability_count['critical'],
            'high_count': self.vulnerability_count['high'],
            'medium_count': self.vulnerability_count['medium'],
            'low_count': self.vulnerability_count['low'],
            'info_count': self.vulnerability_count['info'],
            'vulnerable_count': vulnerable_count,
            'duration': duration,
            'results': self.results,
            'results_json': json.dumps(self.results, default=str)
        }
        
        # Render template
        template = Template(HTML_TEMPLATE)
        html_content = template.render(**template_data)
        
        # Write HTML file
        report_path = os.path.join(self.output_dir, "security_report.html")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[+] HTML report generated: {report_path}")
        
        # Also generate a simple text summary
        self.generate_text_summary()

    def generate_simple_html_report(self):
        """Generate simple HTML report without Jinja2"""
        report_path = os.path.join(self.output_dir, "security_report_simple.html")
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .domain {{ border: 1px solid #ccc; margin: 10px 0; padding: 10px; }}
        .critical {{ border-left: 5px solid red; }}
        .high {{ border-left: 5px solid orange; }}
        .medium {{ border-left: 5px solid yellow; }}
        .low {{ border-left: 5px solid green; }}
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Total Domains: {len(self.results)}</p>
    
    <h2>Vulnerability Summary</h2>
    <p>Critical: {self.vulnerability_count['critical']}</p>
    <p>High: {self.vulnerability_count['high']}</p>
    <p>Medium: {self.vulnerability_count['medium']}</p>
    <p>Low: {self.vulnerability_count['low']}</p>
    
    <h2>Scan Results</h2>
"""
        
        for result in self.results:
            severity_class = result.get('severity', 'info')
            html += f"""
    <div class="domain {severity_class}">
        <h3>{result['domain']} [{severity_class.upper()}]</h3>
        <p>Risk Score: {result.get('risk_score', 0)}</p>
"""
            
            if result.get('port_scan') and result['port_scan'].get('open_ports'):
                ports = ', '.join(map(str, result['port_scan']['open_ports']))
                html += f"<p>Open Ports: {ports}</p>"
            
            if result.get('vulnerabilities'):
                html += "<p>Vulnerabilities:</p><ul>"
                for vuln in result['vulnerabilities']:
                    html += f"<li>{vuln['title']} [{vuln['severity']}]</li>"
                html += "</ul>"
            
            html += "</div>"
        
        html += """
</body>
</html>
"""
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"[+] Simple HTML report generated: {report_path}")

    def generate_text_summary(self):
        """Generate text summary report"""
        summary_path = os.path.join(self.output_dir, "summary.txt")
        
        with open(summary_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("SECURITY SCAN SUMMARY REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Subdomains Scanned: {len(self.results)}\n")
            f.write(f"Scan Duration: {self.get_scan_duration()}\n\n")
            
            f.write("VULNERABILITY STATISTICS:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Critical: {self.vulnerability_count['critical']}\n")
            f.write(f"High: {self.vulnerability_count['high']}\n")
            f.write(f"Medium: {self.vulnerability_count['medium']}\n")
            f.write(f"Low: {self.vulnerability_count['low']}\n")
            f.write(f"Info: {self.vulnerability_count['info']}\n\n")
            
            f.write("CRITICAL FINDINGS:\n")
            f.write("-" * 40 + "\n")
            for finding in self.critical_findings:
                f.write(f"\nDomain: {finding['domain']}\n")
                f.write(f"Risk Score: {finding.get('risk_score', 0)}\n")
                for vuln in finding.get('vulnerabilities', []):
                    if vuln['severity'] in ['critical', 'high']:
                        f.write(f"  • {vuln['title']}: {vuln['description']}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
        
        print(f"[+] Text summary generated: {summary_path}")
    
    def get_scan_duration(self):
        """Calculate total scan duration"""
        if not self.results:
            return "Unknown"
        
        timestamps = []
        for result in self.results:
            try:
                ts = datetime.fromisoformat(result['timestamp'].replace('Z', '+00:00'))
                timestamps.append(ts)
            except:
                pass
        
        if timestamps:
            min_time = min(timestamps)
            max_time = max(timestamps)
            return str(max_time - min_time).split('.')[0]
        
        return "Unknown"

async def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Subdomain Vulnerability Scanner with Advanced Features",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i subdomains.txt                         # Basic scan
  %(prog)s -i subdomains.txt -o ./scan_results       # Custom output directory
  %(prog)s -i subdomains.txt -w 100 -t 15            # 100 workers, 15s timeout
  %(prog)s -i subdomains.txt --email config.json     # Send email alerts
        
Email Config JSON format:
{
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "use_ssl": false,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from": "scanner@example.com",
    "to": ["admin@example.com", "security@example.com"]
}
        """
    )
    
    parser.add_argument("-i", "--input", required=True,
                       help="Input file containing subdomains (one per line)")
    parser.add_argument("-o", "--output", default="scan_results",
                       help="Output directory for results (default: scan_results)")
    parser.add_argument("-w", "--workers", type=int, default=50,
                       help="Maximum concurrent workers (default: 50)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("--email", help="Email configuration JSON file")
    parser.add_argument("--skip-screenshots", action="store_true",
                       help="Skip screenshot capture")
    parser.add_argument("--skip-ports", action="store_true",
                       help="Skip port scanning")
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
    
    # Create scanner instance
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
    print(f"\n[+] Starting comprehensive scan of {len(subdomains)} subdomains")
    print(f"[+] Concurrent workers: {args.workers}")
    print(f"[+] Timeout: {args.timeout}s")
    print(f"[+] Output directory: {args.output}")
    
    if PLAYWRIGHT_AVAILABLE and not args.skip_screenshots:
        print("[+] Screenshot capture: ENABLED")
    else:
        print("[+] Screenshot capture: DISABLED")
    
    if not args.skip_ports:
        print("[+] Port scanning: ENABLED")
    else:
        print("[+] Port scanning: DISABLED")
    
    start_time = datetime.now()
    
    try:
        # Perform scan
        await scanner.scan_batch(subdomains)
        
        # Generate reports
        scanner.generate_report()
        
        # Send email alerts if configured
        if email_config and scanner.critical_findings:
            scanner.send_email_alert()
        
        # Print summary
        elapsed = datetime.now() - start_time
        print("\n" + "="*60)
        print("SCAN COMPLETE")
        print("="*60)
        print(f"[+] Duration: {elapsed}")
        print(f"[+] Total domains scanned: {len(scanner.results)}")
        print(f"[+] Critical findings: {len(scanner.critical_findings)}")
        print(f"[+] Reports saved to: {args.output}/")
        
        if scanner.critical_findings:
            print("\n🚨 CRITICAL FINDINGS SUMMARY:")
            for finding in scanner.critical_findings[:5]:  # Show top 5
                print(f"  • {finding['domain']}: {finding.get('risk_score', 0)} risk points")
            
            if len(scanner.critical_findings) > 5:
                print(f"  ... and {len(scanner.critical_findings) - 5} more")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.save_progress()
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Check for required dependencies
    required = ['aiohttp', 'dns']
    missing = []
    
    for package in required:
        try:
            if package == 'dns':
                import dns.resolver
            elif package == 'aiohttp':
                import aiohttp
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[!] Missing required packages: {', '.join(missing)}")
        print(f"[!] Install with: pip install {' '.join(missing)}")
        sys.exit(1)
    
    # Run the scanner
    asyncio.run(main())
