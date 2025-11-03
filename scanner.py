#!/usr/bin/env python3
"""
Automated Web Vulnerability Scanner
Scans websites for common security vulnerabilities
"""

import requests
import argparse
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import time
from typing import List, Dict, Tuple
import json

class VulnerabilityScanner:
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize the vulnerability scanner
        
        Args:
            target_url: The target website URL to scan
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.results = {
            'target': target_url,
            'vulnerabilities': [],
            'security_headers': {},
            'sensitive_files': [],
            'sql_injection': [],
            'xss_vulnerabilities': [],
            'csrf_vulnerabilities': [],
            'information_disclosure': []
        }
    
    def log_vulnerability(self, severity: str, vulnerability_type: str, description: str, details: Dict | None = None):
        """Log a discovered vulnerability"""
        vuln = {
            'severity': severity,
            'type': vulnerability_type,
            'description': description,
            'details': details or {}
        }
        self.vulnerabilities.append(vuln)
        self.results['vulnerabilities'].append(vuln)
        print(f"[{severity.upper()}] {vulnerability_type}: {description}")
    
    def check_security_headers(self):
        """Check for missing or weak security headers"""
        print("\n[*] Checking security headers...")
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'X-XSS-Protection': 'Enables XSS filtering',
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Content-Security-Policy': 'Controls resource loading',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser features'
            }
            
            self.results['security_headers'] = {}
            for header, description in security_headers.items():
                if header in headers:
                    self.results['security_headers'][header] = headers[header]
                    print(f"[+] Found: {header}: {headers[header]}")
                else:
                    self.results['security_headers'][header] = None
                    self.log_vulnerability(
                        'Medium',
                        'Missing Security Header',
                        f"Missing {header} header",
                        {'description': description}
                    )
        except Exception as e:
            print(f"[-] Error checking security headers: {e}")
    
    def check_sensitive_files(self):
        """Check for commonly exposed sensitive files"""
        print("\n[*] Checking for sensitive files...")
        sensitive_paths = [
            '/.env',
            '/.git/config',
            '/.gitignore',
            '/.htaccess',
            '/.htpasswd',
            '/robots.txt',
            '/sitemap.xml',
            '/web.config',
            '/.well-known/security.txt',
            '/backup.sql',
            '/config.php',
            '/config.json',
            '/package.json',
            '/.dockerignore',
            '/docker-compose.yml',
            '/.DS_Store',
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/admin',
            '/administrator',
            '/wp-admin',
            '/wp-config.php',
            '/.svn/entries',
            '/.idea/workspace.xml'
        ]
        
        for path in sensitive_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if response.status_code == 200:
                    self.results['sensitive_files'].append({
                        'path': path,
                        'status_code': response.status_code,
                        'size': len(response.content)
                    })
                    self.log_vulnerability(
                        'High' if any(ext in path for ext in ['.env', '.htpasswd', 'config.php', 'wp-config.php', 'backup.sql']) else 'Medium',
                        'Sensitive File Exposure',
                        f"Exposed file found: {path}",
                        {'url': url, 'status_code': response.status_code}
                    )
                    print(f"[+] Found exposed file: {path} (Status: {response.status_code})")
            except Exception as e:
                continue
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print("\n[*] Testing for SQL injection vulnerabilities...")
        
        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' /*",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' OR 1=1#",
            "' OR 1=1--",
            "' UNION SELECT * FROM users--",
            "'; DROP TABLE users--",
            "1' OR '1'='1'='1",
        ]
        
        try:
            # Test GET parameters if URL has query string
            parsed = urlparse(self.target_url)
            if parsed.query:
                params = dict([p.split('=') for p in parsed.query.split('&') if '=' in p])
                for param, value in params.items():
                    for payload in sql_payloads[:5]:  # Test first 5 payloads
                        try:
                            test_params = params.copy()
                            test_params[param] = payload
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            response = self.session.get(test_url, params=test_params, timeout=self.timeout)
                            
                            # Check for SQL error messages
                            sql_errors = [
                                'sql syntax', 'mysql_fetch', 'postgresql query failed',
                                'ora-', 'sqlite_', 'sql server', 'odbc', 'access denied',
                                'syntax error', 'sql command', 'warning: mysql'
                            ]
                            
                            content_lower = response.text.lower()
                            for error in sql_errors:
                                if error in content_lower:
                                    self.results['sql_injection'].append({
                                        'parameter': param,
                                        'payload': payload,
                                        'url': response.url
                                    })
                                    self.log_vulnerability(
                                        'Critical',
                                        'SQL Injection',
                                        f"Possible SQL injection in parameter: {param}",
                                        {'payload': payload, 'url': response.url, 'error': error}
                                    )
                                    print(f"[!] Possible SQL injection detected in parameter: {param}")
                                    break
                        except Exception as e:
                            continue
            
            # Test common endpoints
            test_endpoints = [
                '/login',
                '/search',
                '/id',
                '/user',
                '/product',
                '/category'
            ]
            
            for endpoint in test_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    for payload in sql_payloads[:3]:
                        try:
                            response = self.session.get(test_url, params={'id': payload}, timeout=self.timeout)
                            sql_errors = [
                                'sql syntax', 'mysql_fetch', 'postgresql query failed',
                                'ora-', 'sqlite_', 'syntax error'
                            ]
                            content_lower = response.text.lower()
                            for error in sql_errors:
                                if error in content_lower:
                                    self.results['sql_injection'].append({
                                        'endpoint': endpoint,
                                        'payload': payload,
                                        'url': response.url
                                    })
                                    self.log_vulnerability(
                                        'Critical',
                                        'SQL Injection',
                                        f"Possible SQL injection in endpoint: {endpoint}",
                                        {'payload': payload, 'url': response.url}
                                    )
                                    break
                        except:
                            continue
                except:
                    continue
                    
        except Exception as e:
            print(f"[-] Error testing SQL injection: {e}")
    
    def test_xss(self):
        """Test for Cross-Site Scripting (XSS) vulnerabilities"""
        print("\n[*] Testing for XSS vulnerabilities...")
        
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<details open ontoggle=alert("XSS")>'
        ]
        
        try:
            parsed = urlparse(self.target_url)
            if parsed.query:
                params = dict([p.split('=') for p in parsed.query.split('&') if '=' in p])
                for param, value in params.items():
                    for payload in xss_payloads[:3]:
                        try:
                            test_params = params.copy()
                            test_params[param] = payload
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            response = self.session.get(test_url, params=test_params, timeout=self.timeout)
                            
                            # Check if payload is reflected in response
                            if payload in response.text or payload.replace('"', '&quot;') in response.text:
                                self.results['xss_vulnerabilities'].append({
                                    'parameter': param,
                                    'payload': payload,
                                    'url': response.url
                                })
                                self.log_vulnerability(
                                    'High',
                                    'Cross-Site Scripting (XSS)',
                                    f"Possible XSS in parameter: {param} (payload reflected)",
                                    {'payload': payload, 'url': response.url}
                                )
                                print(f"[!] Possible XSS detected in parameter: {param}")
                        except Exception as e:
                            continue
            
            # Test common endpoints
            test_endpoints = ['/search', '/q', '/query', '/s']
            for endpoint in test_endpoints:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    for payload in xss_payloads[:2]:
                        try:
                            response = self.session.get(test_url, params={'q': payload}, timeout=self.timeout)
                            if payload in response.text:
                                self.results['xss_vulnerabilities'].append({
                                    'endpoint': endpoint,
                                    'payload': payload,
                                    'url': response.url
                                })
                                self.log_vulnerability(
                                    'High',
                                    'Cross-Site Scripting (XSS)',
                                    f"Possible XSS in endpoint: {endpoint}",
                                    {'payload': payload, 'url': response.url}
                                )
                        except:
                            continue
                except:
                    continue
                    
        except Exception as e:
            print(f"[-] Error testing XSS: {e}")
    
    def check_csrf(self):
        """Check for CSRF protection"""
        print("\n[*] Checking for CSRF protection...")
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            if forms:
                for form in forms:
                    action = form.get('action', '')
                    # Get method attribute and convert to string, defaulting to 'POST'
                    method_attr = form.get('method')
                    method = str(method_attr[0] if method_attr else 'POST').upper()
                    
                    if method == 'POST':
                        csrf_token = form.find('input', {'name': re.compile(r'csrf|token|_token', re.I)})
                        if not csrf_token:
                            self.results['csrf_vulnerabilities'].append({
                                'form_action': action,
                                'method': method
                            })
                            self.log_vulnerability(
                                'Medium',
                                'CSRF Vulnerability',
                                f"Form without CSRF protection found",
                                {'action': action, 'method': method}
                            )
                            print(f"[!] Form without CSRF token found: {action}")
        except Exception as e:
            print(f"[-] Error checking CSRF: {e}")
    
    def check_information_disclosure(self):
        """Check for information disclosure"""
        print("\n[*] Checking for information disclosure...")
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            
            # Check for common information disclosure patterns
            disclosures = {
                'Server Header': response.headers.get('Server', ''),
                'X-Powered-By': response.headers.get('X-Powered-By', ''),
                'Error Messages': [],
                'Stack Traces': []
            }
            
            # Check for stack traces or error messages in response
            error_patterns = [
                r'Fatal error',
                r'Warning:',
                r'Notice:',
                r'Stack trace:',
                r'at \w+\.\w+',
                r'Exception in thread',
                r'Traceback \(most recent call last\)',
                r'File "[^"]+", line \d+'
            ]
            
            for pattern in error_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    disclosures['Error Messages'].extend(matches[:3])  # Limit to first 3
            
            # Check headers for information disclosure
            if disclosures['Server Header']:
                self.log_vulnerability(
                    'Low',
                    'Information Disclosure',
                    f"Server header reveals: {disclosures['Server Header']}",
                    {'header': 'Server', 'value': disclosures['Server Header']}
                )
            
            if disclosures['X-Powered-By']:
                self.log_vulnerability(
                    'Low',
                    'Information Disclosure',
                    f"X-Powered-By header reveals: {disclosures['X-Powered-By']}",
                    {'header': 'X-Powered-By', 'value': disclosures['X-Powered-By']}
                )
            
            if disclosures['Error Messages']:
                self.results['information_disclosure'].extend(disclosures['Error Messages'])
                self.log_vulnerability(
                    'Medium',
                    'Information Disclosure',
                    "Error messages or stack traces found in response",
                    {'errors': disclosures['Error Messages'][:5]}
                )
            
        except Exception as e:
            print(f"[-] Error checking information disclosure: {e}")
    
    def check_directory_listing(self):
        """Check for directory listing vulnerabilities"""
        print("\n[*] Checking for directory listing...")
        test_paths = ['/images/', '/files/', '/uploads/', '/assets/', '/static/', '/media/', '/public/']
        
        for path in test_paths:
            try:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=self.timeout)
                
                # Check for directory listing indicators
                if any(indicator in response.text.lower() for indicator in [
                    'index of', 'directory listing', '<title>directory of',
                    'parent directory', '[parentdir]', 'directory</a>'
                ]):
                    self.log_vulnerability(
                        'Medium',
                        'Directory Listing',
                        f"Directory listing enabled at: {path}",
                        {'url': url}
                    )
                    print(f"[!] Directory listing found at: {path}")
            except Exception as e:
                continue
    
    def scan(self):
        """Run all vulnerability scans"""
        print(f"\n{'='*60}")
        print(f"Starting vulnerability scan for: {self.target_url}")
        print(f"{'='*60}\n")
        
        try:
            # Test if site is accessible
            response = self.session.get(self.target_url, timeout=self.timeout)
            print(f"[+] Target is accessible (Status: {response.status_code})")
        except Exception as e:
            print(f"[-] Error accessing target: {e}")
            return
        
        # Run all checks
        self.check_security_headers()
        self.check_sensitive_files()
        self.test_sql_injection()
        self.test_xss()
        self.check_csrf()
        self.check_information_disclosure()
        self.check_directory_listing()
        
        # Summary
        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        
        severity_count = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            count = severity_count.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")
        
        return self.results
    
    def export_results(self, filename: str = 'scan_results.json'):
        """Export scan results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\n[+] Results exported to: {filename}")
        except Exception as e:
            print(f"[-] Error exporting results: {e}")


def main():
    parser = argparse.ArgumentParser(description='Automated Web Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', help='Output file for JSON results')
    
    args = parser.parse_args()
    
    scanner = VulnerabilityScanner(args.url, timeout=args.timeout)
    results = scanner.scan()
    
    if args.output:
        scanner.export_results(args.output)
    else:
        scanner.export_results()
    
    return 0 if len(scanner.vulnerabilities) == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

