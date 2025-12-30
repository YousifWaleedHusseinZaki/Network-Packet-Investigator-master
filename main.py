#!/bin/python3

"""Command-line interface for Network Packet Investigator."""

import argparse
import sys
from pathlib import Path

from parsers.pcap_parser import PcapParser
from parsers.dns_parser import DNSParser
from parsers.http_parser import HTTPParser
from parsers.tcp_parser import TCPParser
from analyzers.dns_analyzer import DNSAnalyzer
from analyzers.http_analyzer import HTTPAnalyzer
from analyzers.traffic_analyzer import TrafficAnalyzer
from detectors.exfiltration import ExfiltrationDetector
from detectors.phishing import PhishingDetector
from utils.reporter import Reporter
from utils.config import Colors


def print_banner():
    """Print tool banner."""
    banner = f"""
{Colors.INFO}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║        Network Packet Investigator (NPI) v1.0.0               ║
║        Advanced PCAP Analysis & Threat Detection              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}
    """
    print(banner)


def print_stats(stats):
    """Print PCAP statistics."""
    print(f"{Colors.INFO}[*] PCAP Statistics:{Colors.RESET}")
    print(f"    Total IP Packets: {stats.get('ip_packets', 0)}")
    print(f"    TCP Packets: {stats.get('tcp_packets', 0)}")
    print(f"    UDP Packets: {stats.get('udp_packets', 0)}")
    print(f"    ICMP Packets: {stats.get('icmp_packets', 0)}")
    print(f"    DNS Packets: {stats.get('dns_packets', 0)}")
    print(f"    HTTP Packets: {stats.get('http_packets', 0)}\n")


if __name__ == "__main__":
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description='Network Packet Investigator - Analyze PCAP files for suspicious activities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap
  %(prog)s capture.pcap --output-json report.json
  %(prog)s capture.pcap --analysis dns http
  %(prog)s capture.pcap --skip-phishing
        """
    )
    
    parser.add_argument(
        'pcap_file',
        help='Path to PCAP file to analyze'
    )
    
    parser.add_argument(
        '--output-json',
        metavar='FILE',
        help='Export findings to JSON file'
    )
    
    parser.add_argument(
        '--output-csv',
        metavar='FILE',
        help='Export findings to CSV file'
    )
    
    parser.add_argument(
        '--analysis',
        nargs='+',
        choices=['dns', 'http', 'tcp', 'traffic', 'exfiltration', 'phishing', 'all'],
        default=['all'],
        help='Specific analysis modules to run (default: all)'
    )
    
    parser.add_argument(
        '--skip-phishing',
        action='store_true',
        help='Skip phishing detection'
    )
    
    parser.add_argument(
        '--skip-exfiltration',
        action='store_true',
        help='Skip exfiltration detection'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate PCAP file exists
    if not Path(args.pcap_file).exists():
        print(f"{Colors.CRITICAL}Error: PCAP file not found: {args.pcap_file}{Colors.RESET}")
        sys.exit(1)
        
    print_banner()
    
    try:
        # Initialize reporter
        reporter = Reporter()
        
        # Parse PCAP
        print(f"{Colors.INFO}[*] Initializing parsers...{Colors.RESET}")
        pcap_parser = PcapParser(args.pcap_file)
        packets = pcap_parser.load()
        
        # Get basic statistics
        stats = pcap_parser.get_basic_stats()
        print_stats(stats)
        
        # Initialize parsers
        dns_parser = DNSParser(packets)
        http_parser = HTTPParser(packets)
        tcp_parser = TCPParser(packets)
        
        # Determine which analyses to run
        run_all = 'all' in args.analysis
        run_dns = run_all or 'dns' in args.analysis
        run_http = run_all or 'http' in args.analysis
        run_tcp = run_all or 'tcp' in args.analysis
        run_traffic = run_all or 'traffic' in args.analysis
        run_exfiltration = (run_all or 'exfiltration' in args.analysis) and not args.skip_exfiltration
        run_phishing = (run_all or 'phishing' in args.analysis) and not args.skip_phishing
        
        # Extract data
        print(f"{Colors.INFO}[*] Extracting protocol data...{Colors.RESET}")
        
        if run_dns or run_phishing or run_exfiltration:
            dns_parser.extract_queries()
            dns_parser.extract_responses()
            if args.verbose:
                print(f"    Found {len(dns_parser.queries)} DNS queries")
                
        if run_http or run_phishing or run_exfiltration:
            http_parser.extract_requests()
            http_parser.extract_responses()
            if args.verbose:
                print(f"    Found {len(http_parser.requests)} HTTP requests")
                
        if run_tcp or run_traffic or run_exfiltration:
            tcp_parser.extract_sessions()
            if args.verbose:
                print(f"    Found {len(tcp_parser.sessions)} TCP sessions")
        
        print()
        
        # Run analyses
        print(f"{Colors.SUCCESS}[*] Starting analysis...{Colors.RESET}\n")
        
        if run_dns:
            dns_analyzer = DNSAnalyzer(dns_parser, reporter)
            dns_analyzer.analyze()
            print()
            
        if run_http:
            http_analyzer = HTTPAnalyzer(http_parser, reporter)
            http_analyzer.analyze()
            print()
            
        if run_traffic:
            traffic_analyzer = TrafficAnalyzer(pcap_parser, tcp_parser, reporter)
            traffic_analyzer.analyze()
            print()
            
        if run_exfiltration:
            exfil_detector = ExfiltrationDetector(
                pcap_parser, tcp_parser, http_parser, dns_parser, reporter
            )
            exfil_detector.analyze()
            print()
            
        if run_phishing:
            phishing_detector = PhishingDetector(dns_parser, http_parser, reporter)
            phishing_detector.analyze()
            print()

        # Generate summary
        reporter.generate_summary()

        # Export reports if requested
        if args.output_json: reporter.export_json(args.output_json)
        if args.output_csv: reporter.export_csv(args.output_csv)
            
        print(f"{Colors.SUCCESS}[✓] Analysis complete!{Colors.RESET}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Analysis interrupted by user{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.CRITICAL}[!] Error: {str(e)}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
