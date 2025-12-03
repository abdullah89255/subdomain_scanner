# subdomain_scanner
## Installation and Usage:

### 1. Install Required Dependencies:

```bash
pip install aiohttp dnspython
```

### 2. Prepare Your Subdomains File:
Create a file named `all_subs.txt` with one subdomain per line:
```
example.com
sub1.example.com
sub2.example.com
admin.example.com
api.example.com
```

### 3. Run the Scanner:

```bash
# Basic scan (defaults to 50 concurrent workers)
python3 subdomain_scanner.py -i all_subs.txt

# With custom output file
python3 subdomain_scanner.py -i all_subs.txt -o my_report.html

# With more workers for faster scanning
python3 subdomain_scanner.py -i all_subs.txt -w 100

# Save JSON report as well
python3 subdomain_scanner.py -i all_subs.txt -j results.json
```

### 4. Features Included:

1. **Subdomain Takeover Detection**: Checks for misconfigured DNS pointing to non-existent services
2. **HTTPS/TLS Security**: Validates SSL certificates, checks TLS versions
3. **Security Headers**: Checks for missing security headers (HSTS, CSP, X-Frame-Options, etc.)
4. **CORS Misconfiguration**: Tests for overly permissive CORS policies
5. **Sensitive File Exposure**: Scans for exposed configuration files, backups, etc.
6. **Admin Panel Detection**: Identifies exposed administrative interfaces
7. **Technology Detection**: Identifies web technologies and frameworks
8. **DNS Enumeration**: Gathers DNS records (A
## Installation Instructions:

```bash
# Install required packages
pip install aiohttp dnspython

# Install optional packages for enhanced features
pip install pyopenssl          # For detailed SSL analysis
pip install playwright          # For screenshot capture
pip install python-nmap         # For advanced port scanning
pip install jinja2              # For HTML templating

# Install playwright browsers
playwright install chromium

# Install nmap system package (if not already installed)
# On Kali: sudo apt update && sudo apt install nmap
# On Ubuntu: sudo apt install nmap
# On macOS: brew install nmap
```

## Usage Examples:

```bash
# Basic scan
python3 enhanced_scanner.py -i all_subs.txt

# Scan with all features enabled
python3 enhanced_scanner.py -i all_subs.txt -o ./results -w 100

# Scan with email alerts (create email_config.json first)
python3 enhanced_scanner.py -i all_subs.txt --email email_config.json

# Limit scan to first 100 subdomains
python3 enhanced_scanner.py -i all_subs.txt --limit 100

# Skip screenshots and port scanning
python3 enhanced_scanner.py -i all_subs.txt --skip-screenshots --skip-ports
```

## Features Included:

### 1. **Enhanced Port Scanning**
- Async port scanning for common ports (21, 22, 23, 25, 80, 443, etc.)
- Service banner grabbing
- Integration with nmap for detailed service detection
- Port classification (common, dangerous)

### 2. **Detailed SSL Certificate Analysis**
- Certificate validity and expiration check
- TLS version detection
- Cipher suite analysis
- Key size validation
- Signature algorithm checking
- SSL grading (A-F)

### 3. **Content Discovery**
- Brute-force for common paths (admin panels, config files, backups)
- Detection of sensitive files (.env, config.php, backup.zip)
- Async implementation for speed

### 4. **Screenshot Capture**
- Full-page screenshots using Playwright
- Automatic HTTPS/HTTP fallback
- Screenshots embedded in HTML report

### 5. **Email Integration**
- Send alerts for critical findings
- HTML email with findings summary
- Attach JSON reports and screenshots
- Configurable SMTP settings

### 6. **Comprehensive Reporting**
- Interactive HTML report with filtering
- JSON export
- CSV export
- Text summary
- Risk scoring system

## Email Configuration Example:

Create `email_config.json`:
```json
{
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "use_ssl": false,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from": "security-scanner@yourcompany.com",
    "to": ["security-team@yourcompany.com", "admin@yourcompany.com"]
}
```

The tool is now production-ready with all requested features! The error from the previous code was due to an unterminated triple-quoted string, which is now fixed.
