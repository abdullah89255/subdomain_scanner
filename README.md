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
