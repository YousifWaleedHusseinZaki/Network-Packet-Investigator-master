"""Report generation utilities."""

import json
from datetime import datetime
from tabulate import tabulate
from .config import Colors


class Reporter:
    """Generate reports from analysis results."""
    
    def __init__(self, output_format='text'):
        self.output_format = output_format
        self.findings = []
        
    def add_finding(self, severity, category, description, details=None):
        """Add a finding to the report."""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'description': description,
            'details': details or {}
        }
        self.findings.append(finding)
        
    def print_finding(self, severity, category, description, details=None):
        """Print a finding to console with color coding."""
        color_map = {
            'CRITICAL': Colors.CRITICAL,
            'WARNING': Colors.WARNING,
            'INFO': Colors.INFO
        }
        
        color = color_map.get(severity, Colors.RESET)
        print(f"{color}[{severity}] {category}: {description}{Colors.RESET}")
        
        if details:
            for key, value in details.items():
                print(f"  {key}: {value}")
        print()
        
        self.add_finding(severity, category, description, details)
        
    def generate_summary(self):
        """Generate summary statistics."""
        if not self.findings:
            print(f"{Colors.SUCCESS}✓ No suspicious activity detected{Colors.RESET}\n")
            return
            
        critical = sum(1 for f in self.findings if f['severity'] == 'CRITICAL')
        warnings = sum(1 for f in self.findings if f['severity'] == 'WARNING')
        info = sum(1 for f in self.findings if f['severity'] == 'INFO')
        
        print(f"\n{'='*60}")
        print(f"{Colors.CRITICAL}FINDINGS SUMMARY{Colors.RESET}")
        print(f"{'='*60}")
        print(f"{Colors.CRITICAL}Critical: {critical}{Colors.RESET}")
        print(f"{Colors.WARNING}Warnings: {warnings}{Colors.RESET}")
        print(f"{Colors.INFO}Info: {info}{Colors.RESET}")
        print(f"Total Findings: {len(self.findings)}")
        print(f"{'='*60}\n")
        
    def export_json(self, filename):
        """Export findings to JSON."""
        with open(filename, 'w') as f:
            json.dump(self.findings, f, indent=2)
        print(f"{Colors.SUCCESS}Report exported to {filename}{Colors.RESET}")
        
    def export_csv(self, filename):
        """Export findings to CSV."""
        import csv
        
        if not self.findings:
            return
            
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['timestamp', 'severity', 'category', 'description'])
            writer.writeheader()
            for finding in self.findings:
                row = {k: v for k, v in finding.items() if k != 'details'}
                writer.writerow(row)
        
        print(f"{Colors.SUCCESS}Report exported to {filename}{Colors.RESET}")
