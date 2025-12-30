"""Data exfiltration detector."""

from collections import defaultdict
from utils.config import DATA_EXFIL_THRESHOLD


class ExfiltrationDetector:
    """Detect potential data exfiltration activities."""
    
    def __init__(self, pcap_parser, tcp_parser, http_parser, dns_parser, reporter):
        self.pcap_parser = pcap_parser
        self.tcp_parser = tcp_parser
        self.http_parser = http_parser
        self.dns_parser = dns_parser
        self.reporter = reporter
        
    def analyze(self):
        """Run all exfiltration detection checks."""
        print("[*] Analyzing for data exfiltration...")
        
        self.detect_large_outbound_transfers()
        self.detect_dns_exfiltration()
        self.detect_icmp_exfiltration()
        self.detect_http_exfiltration()
        
    def detect_large_outbound_transfers(self):
        """Detect large outbound data transfers."""
        # Analyze TCP sessions
        top_sessions = self.tcp_parser.get_top_sessions_by_volume(10)
        
        for session in top_sessions:
            # Check if it's primarily outbound
            src_ip = session['session_key'][0]
            outbound_bytes = session['src_to_dst_bytes']
            inbound_bytes = session['dst_to_src_bytes']
            
            # If outbound data is significantly larger
            if outbound_bytes > DATA_EXFIL_THRESHOLD:
                ratio = outbound_bytes / (inbound_bytes + 1)
                
                if ratio > 5:  # Much more outbound than inbound
                    self.reporter.print_finding(
                        'CRITICAL',
                        'Large Outbound Transfer',
                        f'Large data transfer detected from internal host',
                        {
                            'Source IP': src_ip,
                            'Destination IP': session['session_key'][2],
                            'Destination Port': session['session_key'][3],
                            'Outbound Data': f'{outbound_bytes / 1024 / 1024:.2f} MB',
                            'Inbound Data': f'{inbound_bytes / 1024 / 1024:.2f} MB',
                            'Ratio': f'{ratio:.2f}:1'
                        }
                    )
                    
    def detect_dns_exfiltration(self):
        """Detect DNS-based data exfiltration."""
        # Look for patterns indicating DNS tunneling/exfiltration
        domain_query_sizes = defaultdict(list)
        
        for query in self.dns_parser.queries:
            domain = query['query']
            size = len(domain)
            domain_query_sizes[query['src_ip']].append(size)
            
        for src_ip, sizes in domain_query_sizes.items():
            if len(sizes) > 5:  # Multiple queries (lowered from 20)
                avg_size = sum(sizes) / len(sizes)
                
                if avg_size > 25:  # Unusually long queries (lowered from 40)
                    self.reporter.print_finding(
                        'CRITICAL',
                        'DNS Data Exfiltration',
                        f'Potential DNS-based data exfiltration detected',
                        {
                            'Source IP': src_ip,
                            'Query Count': len(sizes),
                            'Average Query Length': f'{avg_size:.2f} chars',
                            'Max Query Length': max(sizes)
                        }
                    )
                    
    def detect_icmp_exfiltration(self):
        """Detect ICMP-based data exfiltration."""
        from scapy.all import ICMP, IP, Raw
        
        icmp_with_large_payload = []
        
        for pkt in self.pcap_parser.packets:
            if ICMP in pkt and Raw in pkt:
                payload_size = len(pkt[Raw].load)
                
                # Normal ICMP ping has small payload (usually 32-56 bytes)
                if payload_size > 100:
                    icmp_with_large_payload.append({
                        'src_ip': pkt[IP].src,
                        'dst_ip': pkt[IP].dst,
                        'payload_size': payload_size,
                        'timestamp': float(pkt.time)
                    })
                    
        if icmp_with_large_payload:
            # Group by source IP
            by_src = defaultdict(list)
            for pkt in icmp_with_large_payload:
                by_src[pkt['src_ip']].append(pkt)
                
            for src_ip, packets in by_src.items():
                if len(packets) > 5:
                    total_bytes = sum(p['payload_size'] for p in packets)
                    
                    self.reporter.print_finding(
                        'CRITICAL',
                        'ICMP Data Exfiltration',
                        f'Potential ICMP-based data exfiltration detected',
                        {
                            'Source IP': src_ip,
                            'ICMP Packets': len(packets),
                            'Total Data': f'{total_bytes / 1024:.2f} KB',
                            'Average Payload': f'{total_bytes / len(packets):.2f} bytes'
                        }
                    )
                    
    def detect_http_exfiltration(self):
        """Detect HTTP-based data exfiltration."""
        # Look for large POST requests
        post_by_src = defaultdict(list)
        
        for request in self.http_parser.requests:
            if request['method'] == 'POST':
                post_by_src[request['src_ip']].append(request)
                
        for src_ip, requests in post_by_src.items():
            total_upload = sum(r.get('content_length', 0) for r in requests)
            
            if total_upload > DATA_EXFIL_THRESHOLD / 2:
                self.reporter.print_finding(
                    'WARNING',
                    'HTTP Data Exfiltration',
                    f'Large volume of HTTP POST data detected',
                    {
                        'Source IP': src_ip,
                        'POST Requests': len(requests),
                        'Total Upload Size': f'{total_upload / 1024 / 1024:.2f} MB',
                        'Destinations': ', '.join(set(r['host'] for r in requests[:5]))
                    }
                )
