#!/usr/bin/env python3
"""
Scanner module for SQLMaster
Handles target validation and initial scanning with false positive detection
"""

import re
import socket
import ssl
from urllib.parse import urlparse
import requests
from rich.console import Console

console = Console()

class SQLScanner:
    def __init__(self, target, config):
        self.target = target
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config['general']['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        })
        self.timeout = config['general']['timeout']
        self.validated_urls = []
        
    def is_modern_spa(self, response_text):
        """Detect if response is a modern SPA (React/Angular/Vue) - LESS AGGRESSIVE"""
        # First check for traditional server-side indicators
        traditional_indicators = [
            '.php?', '.asp?', '.aspx?', '.jsp?', '.pl?', '.cgi?',
            'action="', 'method="post"', 'method="get"',
            '<form', '<input type="submit"', '<select', '<option',
            '<table', '<tr>', '<td>', '<th>'
        ]
        
        response_lower = response_text.lower()
        traditional_count = 0
        for indicator in traditional_indicators:
            if indicator in response_lower:
                traditional_count += 1
        
        # If we have traditional indicators, it's not a pure SPA
        if traditional_count >= 2:
            return False
        
        # Now check for SPA indicators - only STRONG ones
        spa_indicators = [
            '<div id="root"></div>',
            '<div id="app"></div>',
            '<div id="__nuxt"></div>',
            '<div id="__next"></div>',
            '__NEXT_DATA__ =',
            'window.__NUXT__',
            '<script src="/_next/',
            '<script src="/nuxt/',
            'react-dom.production.min.js',
            'vue.runtime.esm-browser.prod.js',
            'angular.min.js',
        ]
        
        strong_spa_count = 0
        for indicator in spa_indicators:
            if indicator.lower() in response_lower:
                strong_spa_count += 1
        
        # Only consider it SPA if we have multiple strong indicators
        return strong_spa_count >= 2
    
    def is_redirect(self, response_text):
        """Detect if response is a redirect"""
        redirect_indicators = [
            '301 Moved Permanently',
            '302 Found',
            '303 See Other',
            '307 Temporary Redirect',
            '308 Permanent Redirect',
            'window.location',
            'window.location.href',
            'window.location.replace',
            'meta http-equiv="refresh"',
            '<meta http-equiv="refresh"',
            'content="0; url=',
            'content="0;url=',
            'Location:',
            'Refresh:',
            'url=',
            'URL='
        ]
        
        response_lower = response_text.lower()
        for indicator in redirect_indicators:
            if indicator.lower() in response_lower:
                return True
        return False
    
    def is_static_content(self, response_text, content_type=None):
        """Detect if response is static content"""
        # Static file extensions that shouldn't be tested
        static_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg',
            '.css', '.js', '.json', '.xml', '.pdf', '.txt', '.csv',
            '.mp4', '.mp3', '.wav', '.avi', '.mov', '.wmv',
            '.zip', '.rar', '.tar', '.gz', '.7z', '.exe', '.dmg',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.ico', '.icns'
        ]
        
        # Check URL for static extensions
        parsed = urlparse(self.target)
        if any(parsed.path.lower().endswith(ext) for ext in static_extensions):
            return True
        
        # Check content-type
        if content_type:
            static_content_types = [
                'image/', 'video/', 'audio/', 'font/', 
                'application/javascript', 'text/css',
                'application/json', 'application/xml',
                'application/pdf', 'application/zip',
                'application/octet-stream'
            ]
            for static_type in static_content_types:
                if static_type in content_type.lower():
                    return True
        
        # Check response content for static indicators
        static_patterns = [
            r'<!DOCTYPE svg',
            r'<svg[^>]*>',
            r'PNG\r\n',
            r'\xFF\xD8\xFF',  # JPEG magic bytes
            r'\x89PNG\r\n',   # PNG magic bytes
            r'GIF8',          # GIF magic bytes
            r'%PDF-',         # PDF magic bytes
            r'PK\x03\x04',    # ZIP magic bytes
        ]
        
        # Check first 1000 bytes for magic bytes
        sample = response_text[:1000] if len(response_text) > 1000 else response_text
        for pattern in static_patterns:
            if re.search(pattern, sample, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    def is_generic_error_page(self, response_text):
        """Detect if response is a generic error page"""
        error_indicators = [
            '404 Not Found',
            '404 - Page Not Found',
            'Page Not Found',
            'Not Found',
            'Error 404',
            '500 Internal Server Error',
            'Internal Server Error',
            'Error 500',
            '502 Bad Gateway',
            '503 Service Unavailable',
            '504 Gateway Timeout',
            '403 Forbidden',
            'Access Denied',
            'Unauthorized',
            'The page cannot be found',
            'This page isn\'t working',
            'Something went wrong',
            'An error occurred',
            'Oops!',
            'We\'re sorry',
            'Sorry, we couldn\'t find that page',
            'The requested URL was not found',
            'The resource you are looking for has been removed',
            'HTTP Error',
            'nginx',  # Generic nginx error
            'Apache',  # Generic Apache error
            'IIS',     # Generic IIS error
        ]
        
        response_lower = response_text.lower()
        count = 0
        for indicator in error_indicators:
            if indicator.lower() in response_lower:
                count += 1
        
        # If multiple error indicators found, likely a generic error page
        return count >= 2
    
    def validate_target(self):
        """Validate and normalize the target URL"""
        console.print(f"[cyan][*] Validating target: {self.target}[/cyan]")
        
        # Add http:// if no scheme specified
        if not self.target.startswith(('http://', 'https://')):
            self.target = f"http://{self.target}"
        
        try:
            parsed = urlparse(self.target)
            
            # Test connection
            response = self.session.head(self.target, timeout=self.timeout, verify=False, allow_redirects=True)
            
            # Check if it's a static file
            if self.is_static_content("", response.headers.get('Content-Type', '')):
                console.print(f"[yellow][!] Target appears to be static content: {self.target}[/yellow]")
                console.print(f"[yellow]    Content-Type: {response.headers.get('Content-Type', 'N/A')}[/yellow]")
                return False
            
            if response.status_code < 400:
                console.print(f"[green][+] Target is accessible: {self.target} (Status: {response.status_code})[/green]")
                return True
            else:
                console.print(f"[yellow][!] Target returned status: {response.status_code}[/yellow]")
                
                # Get full response to check error type
                response_full = self.session.get(self.target, timeout=self.timeout, verify=False, allow_redirects=True)
                if self.is_generic_error_page(response_full.text):
                    console.print(f"[yellow][!] Target returns generic error page (likely doesn't exist)[/yellow]")
                    return False
                
                return True  # Still proceed if not generic error
            
        except requests.exceptions.RequestException as e:
            console.print(f"[red][!] Connection failed: {str(e)}[/red]")
            return False
    
    def discover_parameters(self):
        """Discover parameters from URL"""
        parsed = urlparse(self.target)
        params = {}
        
        if parsed.query:
            from urllib.parse import parse_qs
            params = parse_qs(parsed.query)
            console.print(f"[cyan][*] Found {len(params)} GET parameters[/cyan]")
        
        return {'get': params, 'post': {}, 'cookie': {}, 'header': {}}
    
    def fingerprint_technology(self, response_text=None, headers=None):
        """Fingerprint web technologies"""
        technologies = {
            'server': 'Unknown',
            'language': 'Unknown',
            'framework': 'Unknown',
            'database': 'Unknown',
            'waf': 'Unknown',
            'spa': False,
            'static': False,
            'redirect': False
        }
        
        try:
            if not response_text or not headers:
                response = self.session.get(self.target, timeout=self.timeout, verify=False, allow_redirects=True)
                response_text = response.text
                headers = response.headers
            
            # Check for SPA - but don't trust it completely
            if self.is_modern_spa(response_text):
                technologies['spa'] = True
                # Don't automatically set framework to SPA
            
            # Check for redirect
            if self.is_redirect(response_text):
                technologies['redirect'] = True
            
            # Check for static content
            content_type = headers.get('Content-Type', '')
            if self.is_static_content(response_text, content_type):
                technologies['static'] = True
            
            # Check server header
            if 'Server' in headers:
                technologies['server'] = headers['Server']
            
            # Check for common technology indicators
            if 'X-Powered-By' in headers:
                technologies['framework'] = headers['X-Powered-By']
            
            # Check for common cookies/session tokens
            cookies = headers.get('Set-Cookie', '')
            if cookies:
                cookie_lower = cookies.lower()
                if 'php' in cookie_lower or 'phpsessid' in cookie_lower:
                    technologies['language'] = 'PHP'
                elif 'asp' in cookie_lower or 'aspsession' in cookie_lower:
                    technologies['language'] = 'ASP.NET'
                elif 'jsession' in cookie_lower:
                    technologies['language'] = 'Java'
                elif '.netsession' in cookie_lower:
                    technologies['language'] = '.NET'
            
            # Check URL for server-side extensions
            parsed = urlparse(self.target)
            url_lower = self.target.lower()
            if '.php' in url_lower:
                technologies['language'] = 'PHP'
                technologies['framework'] = 'PHP'
            elif '.aspx' in url_lower or '.asp' in url_lower:
                technologies['language'] = 'ASP.NET'
                technologies['framework'] = 'ASP.NET'
            elif '.jsp' in url_lower:
                technologies['language'] = 'Java'
                technologies['framework'] = 'JSP'
            
            # Check for database indicators in response
            response_lower = response_text.lower()
            db_indicators = {
                'MySQL': ['mysql', 'mysqli', 'mysql_error', 'mysql_fetch', 'you have an error in your sql syntax'],
                'PostgreSQL': ['postgresql', 'pqsql', 'pg_', 'postgres error'],
                'Microsoft SQL Server': ['microsoft sql server', 'sql server', 'mssql', 'sqlsrv', 'odbc', 'ole db', 'sql server native client'],
                'Oracle': ['oracle', 'ora-', 'oracle error', 'pl/sql'],
                'SQLite': ['sqlite', 'sqlite3', 'sqlite error']
            }
            
            for db, indicators in db_indicators.items():
                for indicator in indicators:
                    if indicator in response_lower:
                        technologies['database'] = db
                        break
            
            # Check for WAF
            waf_indicators = {
                'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare', 'cf-cache-status'],
                'ModSecurity': ['mod_security', 'modsecurity'],
                'AWS WAF': ['aws', 'awselb', 'x-amz-cf-'],
                'Akamai': ['akamai', 'x-akamai-'],
                'Imperva': ['imperva', 'incapsula', 'x-cdn'],
                'F5': ['f5', 'bigip', 'x-wa-info'],
                'Barracuda': ['barracuda'],
                'FortiWeb': ['fortiweb']
            }
            
            for waf, indicators in waf_indicators.items():
                for indicator in indicators:
                    if indicator in response_lower or any(indicator.lower() in str(v).lower() for v in headers.values()):
                        technologies['waf'] = waf
                        break
            
            console.print(f"[cyan][*] Technology fingerprint:[/cyan]")
            console.print(f"    Server: {technologies['server']}")
            console.print(f"    Language: {technologies['language']}")
            console.print(f"    Framework: {technologies['framework']}")
            console.print(f"    Database: {technologies['database']}")
            console.print(f"    WAF: {technologies['waf']}")
            
            # Warnings only, don't skip
            if technologies['spa']:
                console.print(f"[yellow][!] Note: Some SPA-like content detected[/yellow]")
                console.print(f"[yellow]    Continuing tests with adjusted expectations...[/yellow]")
            
            if technologies['static']:
                console.print(f"[yellow][!] Warning: Target appears to be static content[/yellow]")
                console.print(f"[yellow]    SQL injection testing is not applicable[/yellow]")
            
            if technologies['redirect']:
                console.print(f"[yellow][!] Warning: Target redirects[/yellow]")
                console.print(f"[yellow]    May need to follow redirects for effective testing[/yellow]")
            
        except requests.exceptions.RequestException:
            console.print("[yellow][!] Could not fingerprint technologies[/yellow]")
        
        return technologies
    
    def should_skip_testing(self, technologies):
        """Determine if testing should be skipped based on technology fingerprint"""
        skip_reasons = []
        
        # Only skip for truly static content
        if technologies.get('static', False):
            skip_reasons.append("Static content (not applicable)")
        
        # Check for generic error pages
        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False, allow_redirects=True)
            if self.is_generic_error_page(response.text):
                skip_reasons.append("Generic error page (endpoint likely doesn't exist)")
        except:
            pass
        
        if skip_reasons:
            console.print(f"[yellow][!] Skipping SQL injection testing for:[/yellow]")
            for reason in skip_reasons:
                console.print(f"[yellow]    - {reason}[/yellow]")
            return True
        
        # NEVER skip for SPA - just warn
        if technologies.get('spa', False):
            console.print(f"[yellow][*] SPA-like content detected, but continuing tests anyway...[/yellow]")
        
        return False
    
    def scan(self):
        """Main scanning method - NEVER SKIP FOR SPA!"""
        if not self.validate_target():
            return None
        
        # Get initial response for fingerprinting
        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False, allow_redirects=True)
            technologies = self.fingerprint_technology(response.text, response.headers)
        except requests.exceptions.RequestException:
            technologies = self.fingerprint_technology()
        
        # Check if testing should be skipped
        if self.should_skip_testing(technologies):
            console.print(f"[yellow][!] Skipping detailed SQL injection tests for this target[/yellow]")
            console.print(f"[yellow]    Consider testing different endpoints or parameters[/yellow]")
            return {
                'url': self.target,
                'technologies': technologies,
                'parameters': self.discover_parameters(),
                'accessible': True,
                'vulnerabilities': [],
                'skipped': True,
                'skip_reason': 'Technology fingerprint indicates likely false positives'
            }
        
        scan_results = {
            'url': self.target,
            'technologies': technologies,
            'parameters': self.discover_parameters(),
            'accessible': True,
            'vulnerabilities': [],
            'skipped': False
        }
        
        return scan_results
