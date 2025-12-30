"""General traffic pattern analyzer."""

from collections import defaultdict, Counter
from utils.config import (
    KNOWN_MALICIOUS_PORTS,
    KNOWN_C2_PORTS,
    TCP_CONNECTION_THRESHOLD
)


class TrafficAnalyzer:
    """Analyze general traffic patterns."""
    
    def __init__(self, pcap_parser, tcp_parser, reporter):
        self.pcap_parser = pcap_parser
        self.tcp_parser = tcp_parser
        self.reporter = reporter
        
    def analyze(self):
        """Run all traffic analysis checks."""
        print("[*] Analyzing traffic patterns...")
        
        self.detect_malicious_ports()
        self.detect_port_scanning()
        self.detect_excessive_connections()
        self.detect_c2_communication()
        self.detect_remote_shell()  # NEW: Detect remote shell commands
        
    def detect_malicious_ports(self):
        """Detect connections to known malicious ports."""
        port_dist = self.tcp_parser.get_port_distribution()
        
        for port, count in port_dist.items():
            if port in KNOWN_MALICIOUS_PORTS:
                self.reporter.print_finding(
                    'CRITICAL',
                    'Malicious Port Activity',
                    f'Traffic detected on known malicious port',
                    {
                        'Port': port,
                        'Connection Count': count,
                        'Description': 'Known backdoor/trojan port'
                    }
                )
                
    def detect_port_scanning(self):
        """Detect potential port scanning activity."""
        # Track unique destination ports per source IP
        src_ports = defaultdict(set)
        
        for pkt in self.pcap_parser.packets:
            from scapy.all import TCP, IP
            if TCP in pkt and IP in pkt:
                src_ports[pkt[IP].src].add(pkt[TCP].dport)
                
        for src_ip, ports in src_ports.items():
            if len(ports) > 50:  # Scanned more than 50 ports
                self.reporter.print_finding(
                    'CRITICAL',
                    'Port Scan Detected',
                    f'Potential port scanning activity detected',
                    {
                        'Source IP': src_ip,
                        'Unique Ports Scanned': len(ports),
                        'Sample Ports': ', '.join(str(p) for p in list(ports)[:10])
                    }
                )
                
    def detect_excessive_connections(self):
        """Detect IPs with excessive connection attempts."""
        connection_counts = defaultdict(int)
        
        for pkt in self.pcap_parser.packets:
            from scapy.all import TCP, IP
            if TCP in pkt and IP in pkt:
                if pkt[TCP].flags & 0x02:  # SYN flag
                    connection_counts[pkt[IP].src] += 1
                    
        for src_ip, count in connection_counts.items():
            if count > TCP_CONNECTION_THRESHOLD:
                self.reporter.print_finding(
                    'WARNING',
                    'Excessive Connections',
                    f'IP making excessive connection attempts',
                    {
                        'Source IP': src_ip,
                        'Connection Attempts': count,
                        'Threshold': TCP_CONNECTION_THRESHOLD
                    }
                )
                
    def detect_c2_communication(self):
        """Detect potential C2 (Command & Control) communication."""
        port_dist = self.tcp_parser.get_port_distribution()
        
        for port, count in port_dist.items():
            if port in KNOWN_C2_PORTS:
                self.reporter.print_finding(
                    'CRITICAL',
                    'Potential C2 Communication',
                    f'Traffic on known C2 port detected',
                    {
                        'Port': port,
                        'Connection Count': count,
                        'Description': 'Common C2/proxy port'
                    }
                )
                
        # Detect beaconing (regular periodic connections)
        self._detect_beaconing()
        
    def _detect_beaconing(self):
        """Detect periodic beaconing behavior."""
        # Group connections by destination IP and analyze timing
        connections_by_dst = defaultdict(list)
        
        for pkt in self.pcap_parser.packets:
            from scapy.all import TCP, IP
            if TCP in pkt and IP in pkt:
                if pkt[TCP].flags & 0x02:  # SYN flag
                    connections_by_dst[pkt[IP].dst].append(float(pkt.time))
                    
        for dst_ip, timestamps in connections_by_dst.items():
            if len(timestamps) < 5:
                continue
                
            # Calculate intervals between connections
            timestamps.sort()
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if len(intervals) > 3:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                std_dev = variance ** 0.5
                
                # If intervals are very regular (low variance), it might be beaconing
                if std_dev < avg_interval * 0.2 and avg_interval > 10:
                    self.reporter.print_finding(
                        'WARNING',
                        'Potential Beaconing Detected',
                        f'Regular periodic connections detected',
                        {
                            'Destination IP': dst_ip,
                            'Connection Count': len(timestamps),
                            'Average Interval': f'{avg_interval:.2f}s',
                            'Std Deviation': f'{std_dev:.2f}s'
                        }
                    )

    def detect_remote_shell(self):
        """Detect remote shell activity in TCP traffic."""
        from scapy.all import TCP, IP, Raw
        
        # Shell indicators to look for
        shell_patterns = [
            # Windows shell prompts
            b'C:\\>',
            b'C:\\Windows',
            b'C:\\Users',
            b'Microsoft Windows',
            b'cmd.exe',
            b'powershell',
            b'PowerShell',
            # Linux shell prompts  
            b'root@',
            b'# ',
            b'$ ',
            b'/bin/bash',
            b'/bin/sh',
            b'uid=',
            b'gid=',
            # Common shell commands
            b'whoami',
            b'ipconfig',
            b'ifconfig',
            b'netstat',
            b'net user',
            b'systeminfo',
            b'uname -a',
            b'cat /etc',
            b'ls -la',
            b'dir ',
            b'cd ',
            b'pwd',
            # Network tools (recon)
            b'nmap',
            b'nc -',
            b'netcat',
            b'wget ',
            b'curl ',
            # Malicious indicators
            b'reverse shell',
            b'bind shell',
            b'meterpreter',
            b'payload',
        ]
        
        shell_connections = []
        reported_sessions = set()
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt and Raw in pkt:
                try:
                    payload = bytes(pkt[Raw].load)
                    src = f"{pkt[IP].src}:{pkt[TCP].sport}"
                    dst = f"{pkt[IP].dst}:{pkt[TCP].dport}"
                    session_key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
                    
                    # Skip if already reported this session
                    if session_key in reported_sessions:
                        continue
                    
                    # Check for shell patterns
                    for pattern in shell_patterns:
                        if pattern in payload:
                            reported_sessions.add(session_key)
                            
                            # Determine if Windows or Linux shell
                            shell_type = 'Windows' if any(p in payload for p in [b'C:\\', b'Microsoft', b'cmd.exe']) else 'Linux/Unix'
                            
                            # Extract a sample of the payload for display
                            try:
                                sample = payload[:200].decode('utf-8', errors='replace')
                            except:
                                sample = payload[:200].hex()
                            
                            shell_connections.append({
                                'src': src,
                                'dst': dst,
                                'port': pkt[TCP].dport,
                                'shell_type': shell_type,
                                'detected_pattern': pattern.decode('utf-8', errors='replace'),
                                'sample': sample
                            })
                            break
                except:
                    continue
        
        # Report findings
        if shell_connections:
            # Group by source for summary
            by_src = defaultdict(list)
            for conn in shell_connections:
                by_src[conn['src'].split(':')[0]].append(conn)
            
            for src_ip, connections in by_src.items():
                conn = connections[0]  # Get first connection details
                
                self.reporter.print_finding(
                    'CRITICAL',
                    'Remote Shell Detected',
                    f'{conn["shell_type"]} remote shell activity detected',
                    {
                        'Source IP': src_ip,
                        'Destination': conn['dst'],
                        'Port': conn['port'],
                        'Shell Type': conn['shell_type'],
                        'Detected Pattern': conn['detected_pattern'],
                        'Shell Sessions': len(connections),
                        'Sample Content': conn['sample'][:100]
                    }
                )
