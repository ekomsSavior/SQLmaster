#!/usr/bin/env python3
"""
Web crawler module for SQLMaster
"""

import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import requests
from rich.console import Console

console = Console()

class WebCrawler:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config['general']['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1'
        })
        self.timeout = config['general']['timeout']
        self.max_depth = config['crawler']['max_depth']
        self.exclude_extensions = config['crawler']['exclude_extensions']
        self.visited_urls = set()
        self.found_urls = []
        
    def should_crawl(self, url):
        """Check if URL should be crawled"""
        parsed = urlparse(url)
        
        # Skip excluded extensions
        for ext in self.exclude_extensions:
            if parsed.path.lower().endswith(ext):
                return False
        
        # Always crawl URLs with query parameters
        if parsed.query:
            return True
        
        # Also crawl common endpoint patterns
        common_patterns = [
            r'.*\.php$',
            r'.*\.asp$',
            r'.*\.aspx$',
            r'.*\.jsp$',
            r'.*\.do$',
            r'.*\.action$',
            r'.*\/api\/.*',
            r'.*\/admin\/.*',
            r'.*\/login\.*',
            r'.*\/search\.*'
        ]
        
        for pattern in common_patterns:
            if re.match(pattern, url, re.IGNORECASE):
                return True
        
        return True
    
    def extract_links(self, url, html_content):
        """Extract links from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        
        # Extract all possible links
        for tag in soup.find_all(['a', 'form', 'link', 'script', 'img', 'iframe']):
            href = None
            
            if tag.name == 'a' and tag.get('href'):
                href = tag['href']
            elif tag.name == 'form' and tag.get('action'):
                href = tag['action']
            elif tag.name in ['link', 'script', 'img', 'iframe'] and tag.get('src'):
                href = tag['src']
            
            if href:
                # Convert relative URLs to absolute
                try:
                    absolute_url = urljoin(url, href)
                    # Clean up the URL
                    absolute_url = absolute_url.split('#')[0]  # Remove fragments
                    if absolute_url and absolute_url not in links:
                        links.append(absolute_url)
                except:
                    continue
        
        # Also look for URLs in JavaScript
        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'["\'](https?://[^"\']+)["\']'
        ]
        
        for pattern in js_patterns:
            for match in re.finditer(pattern, html_content):
                if match.group(1):
                    try:
                        absolute_url = urljoin(url, match.group(1))
                        absolute_url = absolute_url.split('#')[0]
                        if absolute_url and absolute_url not in links:
                            links.append(absolute_url)
                    except:
                        continue
        
        return links
    
    def generate_test_urls(self, base_url):
        """Generate test URLs with common parameters"""
        test_urls = []
        
        # Common parameters to test
        common_params = {
            'id': ['1', '123', 'test'],
            'page': ['1', '2', 'home'],
            'view': ['all', 'single', 'list'],
            'file': ['test.txt', 'index.php'],
            'doc': ['document.pdf', 'readme.txt'],
            'user': ['admin', 'test'],
            'product': ['1', 'test'],
            'category': ['1', 'electronics'],
            'search': ['test', 'admin'],
            'q': ['test', 'admin'],
            's': ['test']
        }
        
        # Add base URL itself
        test_urls.append(base_url)
        
        # Generate URLs with parameters
        for param, values in common_params.items():
            for value in values[:2]:  # Test first 2 values for each parameter
                test_url = f"{base_url}?{param}={value}"
                test_urls.append(test_url)
        
        return test_urls
    
    def crawl(self, start_url, depth=0):
        """Recursive crawling function"""
        if depth > self.max_depth:
            return self.found_urls
        
        if start_url in self.visited_urls:
            return self.found_urls
        
        self.visited_urls.add(start_url)
        
        try:
            console.print(f"[cyan][*] Crawling: {start_url} (depth: {depth})[/cyan]")
            
            # First, add generated test URLs
            generated_urls = self.generate_test_urls(start_url)
            for test_url in generated_urls:
                if test_url not in self.found_urls:
                    self.found_urls.append(test_url)
            
            # Now try to actually visit the page
            response = self.session.get(start_url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            if response.status_code == 200:
                # Add the actual URL to found URLs
                if start_url not in self.found_urls:
                    self.found_urls.append(start_url)
                
                # Extract and follow links
                if 'text/html' in response.headers.get('Content-Type', '').lower():
                    links = self.extract_links(start_url, response.text)
                    
                    for link in links:
                        if self.should_crawl(link) and link not in self.visited_urls:
                            self.crawl(link, depth + 1)
            
        except requests.exceptions.RequestException as e:
            console.print(f"[yellow][!] Failed to crawl {start_url}: {str(e)}[/yellow]")
            # Even if we can't crawl it, add it as a potential target
            if start_url not in self.found_urls:
                self.found_urls.append(start_url)
        
        return self.found_urls
    
    def crawl_domain(self, domain):
        """Crawl entire domain starting from root"""
        start_urls = [
            f"http://{domain}",
            f"https://{domain}",
            f"http://{domain}/index.php",
            f"https://{domain}/index.php",
            f"http://{domain}/index.html",
            f"https://{domain}/index.html"
        ]
        
        console.print(f"[cyan][*] Starting crawl of {domain}[/cyan]")
        
        # Try each starting URL
        for start_url in start_urls:
            try:
                # Quick check if URL is accessible
                response = self.session.head(start_url, timeout=5, verify=False)
                if response.status_code < 400:
                    console.print(f"[green][+] Found accessible URL: {start_url}[/green]")
                    self.crawl(start_url)
                    break
            except:
                continue
        
        # If no URLs found with crawling, at least add the domain
        if not self.found_urls:
            self.found_urls = [f"http://{domain}", f"https://{domain}"]
        
        console.print(f"[green][+] Found {len(self.found_urls)} URLs to test[/green]")
        return self.found_urls
