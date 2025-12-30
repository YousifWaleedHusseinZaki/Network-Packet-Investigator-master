"""Comprehensive attack detector for network traffic analysis."""

import re
from collections import defaultdict


class AttackDetector:
    """Detect various network attacks and threats."""
    
    def __init__(self, pcap_parser, tcp_parser, http_parser, dns_parser, reporter):
        self.pcap_parser = pcap_parser
        self.tcp_parser = tcp_parser
        self.http_parser = http_parser
        self.dns_parser = dns_parser
        self.reporter = reporter
        
    def analyze(self):
        """Run all attack detection checks."""
        print("[*] Running comprehensive attack detection...")
        
        self.detect_arp_spoofing()
        self.detect_sql_injection()
        self.detect_xss_attacks()
        self.detect_directory_traversal()
        self.detect_command_injection()
        self.detect_credential_theft()
        self.detect_brute_force()
        self.detect_suspicious_file_transfers()
        self.detect_malware_signatures()
        self.detect_smb_attacks()
        self.detect_ssh_attacks()
        self.detect_ftp_attacks()
        self.detect_telnet_attacks()
        self.detect_udp_worms()  # SQL Slammer, etc.
        self.detect_icmp_attacks()
        self.detect_dos_attacks()
        
    def detect_arp_spoofing(self):
        """Detect ARP spoofing/poisoning attacks."""
        from scapy.all import ARP
        
        # Track MAC addresses for each IP
        ip_to_mac = defaultdict(set)
        
        for pkt in self.pcap_parser.packets:
            if ARP in pkt:
                src_ip = pkt[ARP].psrc
                src_mac = pkt[ARP].hwsrc
                ip_to_mac[src_ip].add(src_mac)
        
        for ip, macs in ip_to_mac.items():
            if len(macs) > 1:
                self.reporter.print_finding(
                    'CRITICAL',
                    'ARP Spoofing Detected',
                    f'Multiple MAC addresses detected for single IP',
                    {
                        'IP Address': ip,
                        'MAC Addresses': ', '.join(macs),
                        'MAC Count': len(macs),
                        'Attack Type': 'ARP Cache Poisoning'
                    }
                )
                
    def detect_sql_injection(self):
        """Detect SQL injection attempts in HTTP traffic."""
        sql_patterns = [
            r"(?i)(\bunion\b.*\bselect\b)",
            r"(?i)(\bselect\b.*\bfrom\b)",
            r"(?i)(\binsert\b.*\binto\b)",
            r"(?i)(\bdelete\b.*\bfrom\b)",
            r"(?i)(\bdrop\b.*\btable\b)",
            r"(?i)(\bor\b.*=.*\bor\b)",
            r"(?i)('.*or.*'.*=.*')",
            r"(?i)(--\s*$)",
            r"(?i)(/\*.*\*/)",
            r"(?i)(;.*--)",
            r"(?i)(xp_cmdshell)",
            r"(?i)(exec\s*\()",
            r"(?i)(0x[0-9a-f]+)",
            r"(?i)(char\s*\(\s*\d+\s*\))",
            r"(?i)(sleep\s*\(\s*\d+\s*\))",
            r"(?i)(benchmark\s*\()",
            r"(?i)(load_file\s*\()",
            r"(?i)(into\s+outfile)",
        ]
        
        for request in self.http_parser.requests:
            # Check URL path and query string
            path = request.get('path', '')
            host = request.get('host', '')
            
            for pattern in sql_patterns:
                if re.search(pattern, path):
                    self.reporter.print_finding(
                        'CRITICAL',
                        'SQL Injection Attempt',
                        f'SQL injection pattern detected in HTTP request',
                        {
                            'Host': host,
                            'Path': path[:100],
                            'Pattern': pattern[:50],
                            'Source IP': request.get('src_ip', 'Unknown'),
                            'Attack Type': 'SQL Injection'
                        }
                    )
                    break
                    
    def detect_xss_attacks(self):
        """Detect Cross-Site Scripting (XSS) attempts."""
        xss_patterns = [
            r"(?i)(<script[^>]*>)",
            r"(?i)(javascript\s*:)",
            r"(?i)(on\w+\s*=)",
            r"(?i)(eval\s*\()",
            r"(?i)(document\.cookie)",
            r"(?i)(document\.location)",
            r"(?i)(window\.location)",
            r"(?i)(<iframe[^>]*>)",
            r"(?i)(<object[^>]*>)",
            r"(?i)(<embed[^>]*>)",
            r"(?i)(alert\s*\()",
            r"(?i)(prompt\s*\()",
            r"(?i)(confirm\s*\()",
            r"(?i)(<img[^>]*onerror)",
            r"(?i)(<svg[^>]*onload)",
        ]
        
        for request in self.http_parser.requests:
            path = request.get('path', '')
            host = request.get('host', '')
            
            for pattern in xss_patterns:
                if re.search(pattern, path):
                    self.reporter.print_finding(
                        'WARNING',
                        'XSS Attack Attempt',
                        f'Cross-Site Scripting pattern detected',
                        {
                            'Host': host,
                            'Path': path[:100],
                            'Pattern': pattern[:50],
                            'Source IP': request.get('src_ip', 'Unknown'),
                            'Attack Type': 'Reflected XSS'
                        }
                    )
                    break
                    
    def detect_directory_traversal(self):
        """Detect directory traversal/path traversal attacks."""
        traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e/",
            r"%2e%2e\\",
            r"\.\.%2f",
            r"\.\.%5c",
            r"/etc/passwd",
            r"/etc/shadow",
            r"C:\\Windows",
            r"C:/Windows",
            r"boot\.ini",
            r"win\.ini",
        ]
        
        for request in self.http_parser.requests:
            path = request.get('path', '')
            host = request.get('host', '')
            
            for pattern in traversal_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    self.reporter.print_finding(
                        'CRITICAL',
                        'Directory Traversal Attempt',
                        f'Path traversal attack detected',
                        {
                            'Host': host,
                            'Path': path[:100],
                            'Pattern': pattern,
                            'Source IP': request.get('src_ip', 'Unknown'),
                            'Attack Type': 'LFI/Directory Traversal'
                        }
                    )
                    break
                    
    def detect_command_injection(self):
        """Detect OS command injection attempts."""
        cmd_patterns = [
            r"[|;&`$]",
            r"%7c",  # |
            r"%26",  # &
            r"%3b",  # ;
            r"\$\(",
            r"`.*`",
            r"(?i)(ping\s+-)",
            r"(?i)(nslookup\s+)",
            r"(?i)(wget\s+)",
            r"(?i)(curl\s+)",
            r"(?i)(/bin/bash)",
            r"(?i)(/bin/sh)",
            r"(?i)(cmd\.exe)",
            r"(?i)(powershell)",
        ]
        
        for request in self.http_parser.requests:
            path = request.get('path', '')
            host = request.get('host', '')
            
            # Skip static files
            if re.search(r'\.(css|js|png|jpg|gif|ico)$', path, re.IGNORECASE):
                continue
            
            for pattern in cmd_patterns:
                if re.search(pattern, path):
                    self.reporter.print_finding(
                        'CRITICAL',
                        'Command Injection Attempt',
                        f'OS command injection pattern detected',
                        {
                            'Host': host,
                            'Path': path[:100],
                            'Pattern': pattern[:50],
                            'Source IP': request.get('src_ip', 'Unknown'),
                            'Attack Type': 'RCE/Command Injection'
                        }
                    )
                    break
                    
    def detect_credential_theft(self):
        """Detect potential credential theft in traffic."""
        from scapy.all import TCP, IP, Raw
        
        credential_patterns = [
            b'password',
            b'passwd',
            b'pwd=',
            b'pass=',
            b'login',
            b'username',
            b'user=',
            b'email=',
            b'credential',
            b'auth=',
            b'token=',
            b'api_key',
            b'apikey',
            b'secret',
            b'session',
        ]
        
        suspicious_creds = []
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt and Raw in pkt:
                try:
                    payload = bytes(pkt[Raw].load).lower()
                    port = pkt[TCP].dport
                    
                    # Only check unencrypted traffic
                    if port in [80, 8080, 21, 23, 25, 110, 143]:
                        for pattern in credential_patterns:
                            if pattern in payload:
                                suspicious_creds.append({
                                    'src': pkt[IP].src,
                                    'dst': pkt[IP].dst,
                                    'port': port,
                                    'pattern': pattern.decode()
                                })
                                break
                except:
                    continue
        
        if suspicious_creds:
            # Group by source
            by_src = defaultdict(list)
            for cred in suspicious_creds:
                by_src[cred['src']].append(cred)
            
            for src, creds in by_src.items():
                self.reporter.print_finding(
                    'WARNING',
                    'Potential Credential Exposure',
                    f'Credentials may be transmitted in cleartext',
                    {
                        'Source IP': src,
                        'Instances': len(creds),
                        'Destination': creds[0]['dst'],
                        'Port': creds[0]['port'],
                        'Risk': 'Credentials sent over unencrypted connection'
                    }
                )
                
    def detect_brute_force(self):
        """Detect brute force authentication attempts."""
        from scapy.all import TCP, IP
        
        # Track connection attempts to auth ports
        auth_ports = {22: 'SSH', 23: 'Telnet', 21: 'FTP', 3389: 'RDP', 
                      25: 'SMTP', 110: 'POP3', 143: 'IMAP', 445: 'SMB'}
        
        connection_counts = defaultdict(lambda: defaultdict(int))
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt:
                dport = pkt[TCP].dport
                if dport in auth_ports:
                    if pkt[TCP].flags & 0x02:  # SYN flag
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        connection_counts[(src, dst)][dport] += 1
        
        for (src, dst), ports in connection_counts.items():
            for port, count in ports.items():
                if count > 10:  # More than 10 attempts
                    self.reporter.print_finding(
                        'WARNING',
                        'Potential Brute Force Attack',
                        f'Multiple authentication attempts detected',
                        {
                            'Source IP': src,
                            'Destination IP': dst,
                            'Port': port,
                            'Protocol': auth_ports[port],
                            'Attempts': count,
                            'Attack Type': f'{auth_ports[port]} Brute Force'
                        }
                    )
                    
    def detect_suspicious_file_transfers(self):
        """Detect suspicious file transfers."""
        from scapy.all import TCP, IP, Raw
        
        suspicious_extensions = [
            b'.exe', b'.dll', b'.bat', b'.cmd', b'.ps1', b'.vbs',
            b'.scr', b'.pif', b'.msi', b'.jar', b'.hta', b'.wsf',
            b'.com', b'.cpl', b'.reg', b'.lnk'
        ]
        
        malicious_magics = [
            b'MZ',  # PE executable
            b'\x7fELF',  # ELF executable
            b'PK',  # ZIP/Office
        ]
        
        detected = []
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt and Raw in pkt:
                try:
                    payload = bytes(pkt[Raw].load)
                    
                    # Check for suspicious file extensions in content
                    for ext in suspicious_extensions:
                        if ext in payload.lower():
                            detected.append({
                                'src': pkt[IP].src,
                                'dst': pkt[IP].dst,
                                'indicator': ext.decode(),
                                'type': 'extension'
                            })
                            break
                    
                    # Check for executable magic bytes
                    for magic in malicious_magics:
                        if payload.startswith(magic):
                            detected.append({
                                'src': pkt[IP].src,
                                'dst': pkt[IP].dst,
                                'indicator': magic.hex(),
                                'type': 'magic'
                            })
                            break
                except:
                    continue
        
        if detected:
            by_pair = defaultdict(list)
            for d in detected:
                by_pair[(d['src'], d['dst'])].append(d)
            
            for (src, dst), items in by_pair.items():
                self.reporter.print_finding(
                    'WARNING',
                    'Suspicious File Transfer',
                    f'Potentially malicious file transfer detected',
                    {
                        'Source': src,
                        'Destination': dst,
                        'Indicators': len(items),
                        'Type': items[0]['type'],
                        'Sample': items[0]['indicator']
                    }
                )
                
    def detect_malware_signatures(self):
        """Detect known malware signatures and C2 indicators."""
        from scapy.all import TCP, IP, Raw
        
        malware_signatures = [
            # Metasploit/Meterpreter
            (b'meterpreter', 'Meterpreter'),
            (b'msf', 'Metasploit'),
            (b'RHOST', 'Metasploit Config'),
            (b'LHOST', 'Metasploit Config'),
            
            # Cobalt Strike
            (b'beacon', 'Cobalt Strike Beacon'),
            (b'cobaltstrike', 'Cobalt Strike'),
            
            # Empire
            (b'empire', 'PowerShell Empire'),
            (b'New-Object Net.WebClient', 'PowerShell Download'),
            (b'IEX(', 'PowerShell IEX'),
            (b'Invoke-Expression', 'PowerShell Invoke'),
            (b'DownloadString', 'PowerShell Download'),
            
            # Generic malware indicators
            (b'shellcode', 'Shellcode'),
            (b'exploit', 'Exploit'),
            (b'payload', 'Payload'),
            (b'backdoor', 'Backdoor'),
            (b'trojan', 'Trojan'),
            (b'keylogger', 'Keylogger'),
            (b'rootkit', 'Rootkit'),
            
            # Ransomware indicators
            (b'ransom', 'Ransomware'),
            (b'encrypt', 'Encryption'),
            (b'bitcoin', 'Cryptocurrency'),
            (b'decrypt', 'Decryption'),
        ]
        
        detected = defaultdict(list)
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt and Raw in pkt:
                try:
                    payload = bytes(pkt[Raw].load).lower()
                    
                    for signature, name in malware_signatures:
                        if signature.lower() in payload:
                            key = (pkt[IP].src, pkt[IP].dst)
                            detected[key].append(name)
                except:
                    continue
        
        for (src, dst), signatures in detected.items():
            unique_sigs = list(set(signatures))
            self.reporter.print_finding(
                'CRITICAL',
                'Malware Signature Detected',
                f'Known malware indicators found in traffic',
                {
                    'Source': src,
                    'Destination': dst,
                    'Signatures': ', '.join(unique_sigs[:5]),
                    'Count': len(signatures),
                    'Severity': 'HIGH'
                }
            )
            
    def detect_smb_attacks(self):
        """Detect SMB-based attacks (EternalBlue, etc.)."""
        from scapy.all import TCP, IP, Raw
        
        smb_attacks = []
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt:
                if pkt[TCP].dport == 445 or pkt[TCP].sport == 445:
                    if Raw in pkt:
                        payload = bytes(pkt[Raw].load)
                        
                        # EternalBlue indicators
                        if b'\x00\x00\x00\x00\xfe' in payload or len(payload) > 1000:
                            smb_attacks.append({
                                'src': pkt[IP].src,
                                'dst': pkt[IP].dst,
                                'size': len(payload)
                            })
        
        if smb_attacks:
            by_pair = defaultdict(list)
            for a in smb_attacks:
                by_pair[(a['src'], a['dst'])].append(a)
            
            for (src, dst), attacks in by_pair.items():
                if len(attacks) > 5:
                    self.reporter.print_finding(
                        'CRITICAL',
                        'SMB Attack Detected',
                        f'Suspicious SMB activity detected (possible exploit)',
                        {
                            'Source': src,
                            'Destination': dst,
                            'Suspicious Packets': len(attacks),
                            'Attack Type': 'SMB Exploit (EternalBlue/MS17-010)'
                        }
                    )
                    
    def detect_ssh_attacks(self):
        """Detect SSH-based attacks."""
        from scapy.all import TCP, IP
        
        ssh_connections = defaultdict(int)
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt:
                if pkt[TCP].dport == 22:
                    if pkt[TCP].flags & 0x02:  # SYN
                        ssh_connections[(pkt[IP].src, pkt[IP].dst)] += 1
        
        for (src, dst), count in ssh_connections.items():
            if count > 20:
                self.reporter.print_finding(
                    'WARNING',
                    'SSH Brute Force Attack',
                    f'Multiple SSH connection attempts detected',
                    {
                        'Source': src,
                        'Destination': dst,
                        'Attempts': count,
                        'Attack Type': 'SSH Password Spray'
                    }
                )
                
    def detect_ftp_attacks(self):
        """Detect FTP-based attacks and anonymous access."""
        from scapy.all import TCP, IP, Raw
        
        ftp_issues = []
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt and Raw in pkt:
                if pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                    try:
                        payload = bytes(pkt[Raw].load)
                        
                        # Anonymous login
                        if b'anonymous' in payload.lower():
                            ftp_issues.append({
                                'type': 'Anonymous Login',
                                'src': pkt[IP].src,
                                'dst': pkt[IP].dst
                            })
                        
                        # Common FTP attacks
                        if b'SITE EXEC' in payload.upper():
                            ftp_issues.append({
                                'type': 'FTP Command Execution',
                                'src': pkt[IP].src,
                                'dst': pkt[IP].dst
                            })
                    except:
                        continue
        
        if ftp_issues:
            for issue in ftp_issues[:5]:
                self.reporter.print_finding(
                    'WARNING',
                    'FTP Security Issue',
                    f'{issue["type"]} detected',
                    {
                        'Source': issue['src'],
                        'Destination': issue['dst'],
                        'Issue': issue['type']
                    }
                )
                
    def detect_telnet_attacks(self):
        """Detect Telnet-based attacks."""
        from scapy.all import TCP, IP, Raw
        
        telnet_sessions = defaultdict(list)
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt:
                if pkt[TCP].dport == 23 or pkt[TCP].sport == 23:
                    telnet_sessions[(pkt[IP].src, pkt[IP].dst)].append(pkt)
        
        for (src, dst), packets in telnet_sessions.items():
            if len(packets) > 5:
                self.reporter.print_finding(
                    'WARNING',
                    'Telnet Activity Detected',
                    f'Unencrypted Telnet session detected',
                    {
                        'Source': src,
                        'Destination': dst,
                        'Packets': len(packets),
                        'Risk': 'Credentials transmitted in cleartext'
                    }
                )
                
    def detect_udp_worms(self):
        """Detect UDP-based worms like SQL Slammer."""
        from scapy.all import UDP, IP, Raw
        
        # Known worm ports and signatures
        worm_indicators = {
            1434: {  # SQL Slammer
                'name': 'SQL Slammer Worm',
                'signatures': [b'\x04\x01\x01\x01\x01', b'\x68\x2e\x64\x6c\x6c'],
                'min_size': 300,
                'max_size': 400,
            },
            69: {  # TFTP-based worms
                'name': 'TFTP Worm',
                'signatures': [],
                'min_size': 0,
                'max_size': 0,
            },
            137: {  # NetBIOS worms
                'name': 'NetBIOS Worm',
                'signatures': [],
                'min_size': 0,
                'max_size': 0,
            },
            161: {  # SNMP worms
                'name': 'SNMP Worm',
                'signatures': [],
                'min_size': 0,
                'max_size': 0,
            }
        }
        
        udp_attacks = defaultdict(list)
        
        for pkt in self.pcap_parser.packets:
            if UDP in pkt and IP in pkt:
                dport = pkt[UDP].dport
                sport = pkt[UDP].sport
                src = pkt[IP].src
                dst = pkt[IP].dst
                
                # Check for SQL Slammer (UDP 1434, ~376 bytes)
                if dport == 1434:
                    pkt_len = len(pkt)
                    if 300 <= pkt_len <= 450:
                        udp_attacks['SQL Slammer'].append({
                            'src': src,
                            'dst': dst,
                            'port': dport,
                            'size': pkt_len
                        })
                        
                # Check for any suspicious UDP to worm ports
                if dport in worm_indicators or sport in worm_indicators:
                    port = dport if dport in worm_indicators else sport
                    worm_info = worm_indicators[port]
                    
                    if Raw in pkt:
                        payload = bytes(pkt[Raw].load)
                        # Check signatures
                        for sig in worm_info.get('signatures', []):
                            if sig in payload:
                                udp_attacks[worm_info['name']].append({
                                    'src': src,
                                    'dst': dst,
                                    'port': port,
                                    'size': len(pkt)
                                })
                                break
                                
                # Generic UDP flood detection (many packets to same dest)
                udp_attacks['UDP_' + dst].append({
                    'src': src,
                    'dst': dst,
                    'port': dport,
                    'size': len(pkt)
                })
        
        # Report SQL Slammer specifically
        if 'SQL Slammer' in udp_attacks and udp_attacks['SQL Slammer']:
            attacks = udp_attacks['SQL Slammer']
            self.reporter.print_finding(
                'CRITICAL',
                'SQL Slammer Worm Detected',
                f'SQL Slammer worm traffic detected (CVE-2002-0649)',
                {
                    'Attack Type': 'SQL Slammer Worm',
                    'Protocol': 'UDP',
                    'Target Port': 1434,
                    'Packets': len(attacks),
                    'Source': attacks[0]['src'],
                    'Destination': attacks[0]['dst'],
                    'Packet Size': f"{attacks[0]['size']} bytes",
                    'CVE': 'CVE-2002-0649',
                    'Severity': 'CRITICAL'
                }
            )
        
        # Report any other worm detections
        for worm_name, attacks in udp_attacks.items():
            if worm_name.startswith('UDP_') or worm_name == 'SQL Slammer':
                continue
            if attacks:
                self.reporter.print_finding(
                    'CRITICAL',
                    f'{worm_name} Detected',
                    f'Network worm activity detected',
                    {
                        'Worm': worm_name,
                        'Packets': len(attacks),
                        'Source': attacks[0]['src'],
                        'Destination': attacks[0]['dst']
                    }
                )
                
    def detect_icmp_attacks(self):
        """Detect ICMP-based attacks (ping flood, smurf, etc.)."""
        from scapy.all import ICMP, IP
        
        icmp_counts = defaultdict(int)
        icmp_types = defaultdict(int)
        
        for pkt in self.pcap_parser.packets:
            if ICMP in pkt and IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                icmp_type = pkt[ICMP].type
                
                icmp_counts[(src, dst)] += 1
                icmp_types[icmp_type] += 1
        
        # Detect ICMP flood
        for (src, dst), count in icmp_counts.items():
            if count > 50:  # More than 50 ICMP packets
                self.reporter.print_finding(
                    'WARNING',
                    'ICMP Flood Detected',
                    f'Excessive ICMP traffic detected (possible ping flood)',
                    {
                        'Source': src,
                        'Destination': dst,
                        'ICMP Packets': count,
                        'Attack Type': 'Ping Flood/DoS'
                    }
                )
        
        # Detect ICMP timestamp/address mask requests (recon)
        recon_types = {13: 'Timestamp Request', 17: 'Address Mask Request'}
        for icmp_type, count in icmp_types.items():
            if icmp_type in recon_types and count > 5:
                self.reporter.print_finding(
                    'INFO',
                    'ICMP Reconnaissance',
                    f'{recon_types[icmp_type]} detected (network discovery)',
                    {
                        'ICMP Type': icmp_type,
                        'Type Name': recon_types[icmp_type],
                        'Count': count,
                        'Risk': 'Network reconnaissance'
                    }
                )
                
    def detect_dos_attacks(self):
        """Detect various denial of service attack patterns."""
        from scapy.all import TCP, IP
        
        # SYN flood detection
        syn_counts = defaultdict(int)
        
        for pkt in self.pcap_parser.packets:
            if TCP in pkt and IP in pkt:
                # Count SYN packets without ACK (half-open connections)
                if pkt[TCP].flags == 0x02:  # SYN only
                    dst = pkt[IP].dst
                    dport = pkt[TCP].dport
                    syn_counts[(dst, dport)] += 1
        
        for (dst, dport), count in syn_counts.items():
            if count > 50:  # More than 50 SYN packets
                self.reporter.print_finding(
                    'CRITICAL',
                    'SYN Flood Detected',
                    f'Potential SYN flood attack detected',
                    {
                        'Target IP': dst,
                        'Target Port': dport,
                        'SYN Packets': count,
                        'Attack Type': 'TCP SYN Flood DoS'
                    }
                )
