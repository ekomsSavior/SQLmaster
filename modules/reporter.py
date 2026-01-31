#!/usr/bin/env python3
"""
Report generation module for SQLMaster
"""

import json
import os
from datetime import datetime
from rich.console import Console

console = Console()

class ReportGenerator:
    def __init__(self, config):
        self.config = config
        
    def generate_report(self, results):
        """Generate a comprehensive report"""
        if not results:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_file = f"results/report_{timestamp}.txt"
        json_file = f"results/report_{timestamp}.json"
        
        # Save JSON report
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate TXT report
        self.generate_txt_report(results, txt_file)
        
        console.print(f"[green][+] Report saved as: {txt_file}[/green]")
        console.print(f"[green][+] JSON data saved as: {json_file}[/green]")
        
        return txt_file
    
    def generate_txt_report(self, results, filename):
        """Generate text report for bug bounty"""
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("SQL INJECTION VULNERABILITY REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Tool: SQLMaster v1.0\n")
            f.write(f"Total Vulnerabilities Found: {len(results)}\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            
            # Count by type
            vuln_types = {}
            for vuln in results:
                vuln_type = vuln['type']
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            f.write("Vulnerability Summary:\n")
            for vuln_type, count in vuln_types.items():
                f.write(f"  - {vuln_type}: {count}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("=" * 80 + "\n\n")
            
            for i, vuln in enumerate(results, 1):
                f.write(f"Finding #{i}\n")
                f.write("-" * 40 + "\n")
                f.write(f"Type: {vuln['type']}\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Parameter: {vuln.get('parameter', 'N/A')}\n")
                f.write(f"Payload: {vuln.get('payload', 'N/A')}\n")
                f.write(f"Confidence: {vuln.get('confidence', 'N/A')}\n")
                
                if 'db_error' in vuln:
                    f.write(f"Database Error: {vuln['db_error']}\n")
                
                if 'columns' in vuln:
                    f.write(f"Columns: {vuln['columns']}\n")
                
                if 'delay' in vuln:
                    f.write(f"Delay: {vuln['delay']} seconds\n")
                
                f.write(f"Status Code: {vuln.get('status_code', 'N/A')}\n")
                f.write(f"Response Time: {vuln.get('response_time', 'N/A')}s\n")
                
                f.write("\nProof of Concept:\n")
                f.write(f"  1. Navigate to: {vuln['url']}\n")
                f.write(f"  2. Observe the SQL error/time delay/response difference\n")
                f.write(f"  3. Parameter '{vuln.get('parameter')}' is vulnerable\n\n")
                
                f.write("Remediation:\n")
                f.write("  1. Use parameterized queries/prepared statements\n")
                f.write("  2. Implement proper input validation and sanitization\n")
                f.write("  3. Apply the principle of least privilege\n")
                f.write("  4. Use a Web Application Firewall (WAF)\n")
                f.write("  5. Regular security testing and code reviews\n\n")
                
                f.write("Severity: ")
                if 'Error-based' in vuln['type'] or 'Union-based' in vuln['type']:
                    f.write("CRITICAL\n\n")
                elif 'Time-based' in vuln['type']:
                    f.write("HIGH\n\n")
                elif 'Boolean' in vuln['type']:
                    f.write("MEDIUM\n\n")
                else:
                    f.write("LOW\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("1. Input Validation:\n")
            f.write("   - Validate all user inputs on the server side\n")
            f.write("   - Use whitelist validation where possible\n")
            f.write("   - Implement proper data type checking\n\n")
            
            f.write("2. Database Security:\n")
            f.write("   - Use parameterized queries exclusively\n")
            f.write("   - Apply principle of least privilege to database accounts\n")
            f.write("   - Regularly update database software\n\n")
            
            f.write("3. Monitoring & Logging:\n")
            f.write("   - Implement comprehensive logging of SQL queries\n")
            f.write("   - Monitor for suspicious database activity\n")
            f.write("   - Set up alerts for SQL error patterns\n\n")
            
            f.write("4. Defense in Depth:\n")
            f.write("   - Implement a Web Application Firewall (WAF)\n")
            f.write("   - Use database firewalls\n")
            f.write("   - Conduct regular penetration tests\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("DISCLAIMER\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("This report is for authorized security testing only.\n")
            f.write("All findings should be handled responsibly and in accordance\n")
            f.write("with applicable laws and regulations.\n")
            f.write("Do not test on systems without explicit permission.\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")
