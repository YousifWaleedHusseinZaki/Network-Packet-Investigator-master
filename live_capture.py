"""Live packet capture module for real-time network monitoring."""

import threading
import time
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, get_if_list, get_if_hwaddr, IP, TCP, UDP, ICMP, Raw, DNS, conf


class LiveCapture:
    """Live packet capture engine with real-time streaming."""
    
    def __init__(self, socketio):
        self.socketio = socketio
        self.capturing = False
        self.paused = False
        self.capture_thread = None
        self.interface = None
        self.filter = None
        self.packets = []
        self.raw_packets = []  # Store raw scapy packets for saving to PCAP
        self.packet_count = 0
        self.bytes_captured = 0
        self.start_time = None
        self.stats = defaultdict(int)
        
    def get_interfaces(self):
        """Get list of active network interfaces (with IP addresses)."""
        interfaces = []
        all_interfaces = []
        
        try:
            # Method 1: Use scapy's IFACES (Windows-friendly)
            from scapy.arch.windows import get_windows_if_list
            try:
                win_ifaces = get_windows_if_list()
                for iface in win_ifaces:
                    # Get IPv4 addresses (filter out IPv6)
                    ips = iface.get('ips', [])
                    ipv4 = [ip for ip in ips if ip and '.' in ip and not ip.startswith('169.254')]
                    
                    # Construct robust ID (device name)
                    guid = iface.get('guid', '')
                    name = iface.get('name', guid)
                    if guid and not name.startswith('\\Device\\'):
                        # Use the NPF device path which scapy prefers
                        robust_id = f'\\Device\\NPF_{guid}'
                    else:
                        robust_id = name

                    iface_info = {
                        'id': robust_id,
                        'name': name,
                        'mac': iface.get('mac', 'Unknown'),
                        'description': iface.get('description', name),
                        'ip': ipv4[0] if ipv4 else ''
                    }
                    all_interfaces.append(iface_info)
                    
                    # Only include active interfaces (with valid IP)
                    if ipv4:
                        interfaces.append(iface_info)
                        
                if interfaces:
                    return interfaces
                # Fall back to all if no active found
                if all_interfaces:
                    return all_interfaces
            except Exception as e:
                print(f"Windows interface method failed: {e}")
            
            # Method 2: Use scapy's conf.ifaces
            try:
                from scapy.config import conf
                if hasattr(conf, 'ifaces'):
                    for name, iface in conf.ifaces.items():
                        ip = getattr(iface, 'ip', '')
                        # Skip interfaces without IP or with link-local
                        if ip and '.' in ip and not ip.startswith('169.254'):
                            interfaces.append({
                                'id': name,  # conf.ifaces keys are usually safe
                                'name': name,
                                'mac': getattr(iface, 'mac', 'Unknown'),
                                'description': getattr(iface, 'description', name),
                                'ip': ip
                            })
                if interfaces:
                    return interfaces
            except Exception as e:
                print(f"Scapy ifaces method failed: {e}")
            
            # Method 3: Use get_if_list (basic) - can't filter active
            iface_list = get_if_list()
            for iface in iface_list:
                try:
                    mac = get_if_hwaddr(iface)
                    interfaces.append({
                        'id': iface,
                        'name': iface,
                        'mac': mac,
                        'description': iface,
                        'ip': ''
                    })
                except:
                    pass  # Skip interfaces we can't get MAC for
                    
        except Exception as e:
            print(f"Error getting interfaces: {e}")
        
        # If still no interfaces, add a message interface
        if not interfaces:
            interfaces.append({
                'name': '',
                'mac': '',
                'description': '⚠️ No active interfaces - Run as Administrator',
                'ip': ''
            })
            
        return interfaces
    
    def start_capture(self, interface=None, bpf_filter=None):
        """Start live packet capture."""
        if self.capturing:
            return {'error': 'Capture already running'}
        
        self.interface = interface
        self.filter = bpf_filter
        self.capturing = True
        self.paused = False
        self.packets = []
        self.raw_packets = []  # Clear for new capture
        self.packet_count = 0
        self.bytes_captured = 0
        self.start_time = datetime.now()
        self.stats = defaultdict(int)
        
        # Start capture in background thread
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
        self.socketio.emit('capture_status', {
            'status': 'started',
            'interface': interface,
            'filter': bpf_filter,
            'timestamp': self.start_time.isoformat()
        })
        
        return {'status': 'started', 'interface': interface}
    
    def stop_capture(self):
        """Stop live packet capture."""
        self.capturing = False
        
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
            
        duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        self.socketio.emit('capture_status', {
            'status': 'stopped',
            'packet_count': self.packet_count,
            'bytes_captured': self.bytes_captured,
            'duration': duration,
            'stats': dict(self.stats)
        })
        
        return {
            'status': 'stopped',
            'packet_count': self.packet_count,
            'bytes_captured': self.bytes_captured,
            'duration': duration
        }
    
    def pause_capture(self):
        """Pause/resume capture."""
        self.paused = not self.paused
        status = 'paused' if self.paused else 'resumed'
        
        self.socketio.emit('capture_status', {
            'status': status,
            'packet_count': self.packet_count
        })
        
        return {'status': status}
    
    def _capture_loop(self):
        """Main capture loop running in background thread."""
        try:
            sniff(
                iface=self.interface,
                filter=self.filter,
                prn=self._process_packet,
                stop_filter=lambda x: not self.capturing,
                store=False
            )
        except Exception as e:
            self.socketio.emit('capture_error', {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            self.capturing = False
    
    def _process_packet(self, pkt):
        """Process a captured packet and emit to frontend."""
        if self.paused:
            return
        
        # Store raw packet for PCAP saving
        self.raw_packets.append(pkt)
            
        self.packet_count += 1
        pkt_len = len(pkt)
        self.bytes_captured += pkt_len
        
        # Build packet data
        pkt_data = {
            'index': self.packet_count,
            'timestamp': float(pkt.time),
            'length': pkt_len,
            'protocol': 'Other',
            'src_ip': '',
            'dst_ip': '',
            'src_port': None,
            'dst_port': None,
            'info': '',
            'summary': pkt.summary(),
            'threat_level': 'none',  # none, low, medium, high, critical
            'payload': ''
        }
        
        # Extract IP layer
        if IP in pkt:
            pkt_data['src_ip'] = pkt[IP].src
            pkt_data['dst_ip'] = pkt[IP].dst
            pkt_data['protocol'] = 'IP'
            
            # TCP
            if TCP in pkt:
                pkt_data['protocol'] = 'TCP'
                pkt_data['src_port'] = pkt[TCP].sport
                pkt_data['dst_port'] = pkt[TCP].dport
                pkt_data['info'] = f"TCP {pkt[TCP].sport} → {pkt[TCP].dport}"
                
                # Check for HTTP
                if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                    pkt_data['protocol'] = 'HTTP'
                elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                    pkt_data['protocol'] = 'HTTPS'
                elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                    pkt_data['protocol'] = 'SSH'
                elif pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                    pkt_data['protocol'] = 'FTP'
                    
            # UDP
            elif UDP in pkt:
                pkt_data['protocol'] = 'UDP'
                pkt_data['src_port'] = pkt[UDP].sport
                pkt_data['dst_port'] = pkt[UDP].dport
                pkt_data['info'] = f"UDP {pkt[UDP].sport} → {pkt[UDP].dport}"
                
                # Check for DNS
                if DNS in pkt:
                    pkt_data['protocol'] = 'DNS'
                    if pkt[DNS].qr == 0:  # Query
                        if pkt[DNS].qd:
                            pkt_data['info'] = f"DNS Query: {pkt[DNS].qd.qname.decode()}"
                    else:  # Response
                        pkt_data['info'] = "DNS Response"
                        
                # Check for specific UDP ports
                if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                    pkt_data['protocol'] = 'DNS'
                elif pkt[UDP].dport == 67 or pkt[UDP].dport == 68:
                    pkt_data['protocol'] = 'DHCP'
                elif pkt[UDP].dport == 123:
                    pkt_data['protocol'] = 'NTP'
                    
            # ICMP
            elif ICMP in pkt:
                pkt_data['protocol'] = 'ICMP'
                icmp_type = pkt[ICMP].type
                if icmp_type == 8:
                    pkt_data['info'] = "Echo Request (ping)"
                elif icmp_type == 0:
                    pkt_data['info'] = "Echo Reply"
                else:
                    pkt_data['info'] = f"ICMP Type {icmp_type}"
        
        # Extract payload preview
        if Raw in pkt:
            try:
                payload = bytes(pkt[Raw].load)[:100]
                pkt_data['payload'] = payload.decode('utf-8', errors='replace')
            except:
                pass
        
        # Quick threat detection
        pkt_data['threat_level'] = self._quick_threat_check(pkt, pkt_data)
        
        # Update stats
        self.stats[pkt_data['protocol']] += 1
        
        # Emit packet to frontend
        self.socketio.emit('packet', pkt_data)
        
        # Emit stats update every 10 packets
        if self.packet_count % 10 == 0:
            duration = (datetime.now() - self.start_time).total_seconds()
            self.socketio.emit('capture_stats', {
                'packet_count': self.packet_count,
                'bytes_captured': self.bytes_captured,
                'packets_per_sec': round(self.packet_count / duration, 1) if duration > 0 else 0,
                'protocols': dict(self.stats),
                'duration': round(duration, 1)
            })
    
    def _quick_threat_check(self, pkt, pkt_data):
        """Quick threat level assessment."""
        # Check for suspicious ports
        suspicious_ports = [4444, 5555, 6666, 1337, 31337, 12345, 54321]
        
        src_port = pkt_data.get('src_port')
        dst_port = pkt_data.get('dst_port')
        
        if src_port in suspicious_ports or dst_port in suspicious_ports:
            return 'high'
        
        # Check for potential shell commands in payload
        if pkt_data.get('payload'):
            payload_lower = pkt_data['payload'].lower()
            shell_indicators = ['cmd', 'powershell', '/bin/sh', '/bin/bash', 'whoami', 'net user']
            for indicator in shell_indicators:
                if indicator in payload_lower:
                    return 'critical'
        
        # Check for suspicious DNS
        if pkt_data['protocol'] == 'DNS' and Raw in pkt:
            # Long DNS query might indicate tunneling
            if len(pkt[Raw].load) > 100:
                return 'medium'
        
        return 'none'
    
    def get_stats(self):
        """Get current capture statistics."""
        if not self.start_time:
            return {'status': 'idle'}
            
        duration = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'status': 'capturing' if self.capturing else 'stopped',
            'paused': self.paused,
            'packet_count': self.packet_count,
            'bytes_captured': self.bytes_captured,
            'duration': round(duration, 1),
            'packets_per_sec': round(self.packet_count / duration, 1) if duration > 0 else 0,
            'protocols': dict(self.stats),
            'interface': self.interface,
            'filter': self.filter
        }
    
    def save_to_pcap(self, filename):
        """Save captured packets to a PCAP file."""
        from scapy.all import wrpcap
        
        if not self.raw_packets:
            return {'error': 'No packets to save', 'success': False}
        
        try:
            wrpcap(filename, self.raw_packets)
            return {
                'success': True,
                'filename': filename,
                'packet_count': len(self.raw_packets),
                'bytes': self.bytes_captured
            }
        except Exception as e:
            return {'error': str(e), 'success': False}
