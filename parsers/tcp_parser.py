"""TCP session parser and extractor."""

from scapy.all import TCP, IP
from collections import defaultdict


class TCPParser:
    """Extract and analyze TCP sessions."""
    
    def __init__(self, packets):
        self.packets = packets
        self.sessions = defaultdict(list)
        self.connections = []
        
    def extract_sessions(self):
        """Extract TCP sessions (conversations)."""
        for pkt in self.packets:
            if TCP in pkt and IP in pkt:
                # Create session key
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                
                # Normalize session key (bidirectional)
                if (src_ip, src_port) < (dst_ip, dst_port):
                    session_key = (src_ip, src_port, dst_ip, dst_port)
                else:
                    session_key = (dst_ip, dst_port, src_ip, src_port)
                    
                packet_info = {
                    'timestamp': float(pkt.time),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'flags': self._get_tcp_flags(pkt[TCP]),
                    'seq': pkt[TCP].seq,
                    'ack': pkt[TCP].ack,
                    'payload_size': len(pkt[TCP].payload) if pkt[TCP].payload else 0
                }
                
                self.sessions[session_key].append(packet_info)
                
        return dict(self.sessions)
        
    def get_connection_attempts(self):
        """Get TCP connection attempts (SYN packets)."""
        syn_packets = []
        
        for pkt in self.packets:
            if TCP in pkt and IP in pkt:
                if pkt[TCP].flags & 0x02:  # SYN flag
                    connection = {
                        'timestamp': float(pkt.time),
                        'src_ip': pkt[IP].src,
                        'dst_ip': pkt[IP].dst,
                        'src_port': pkt[TCP].sport,
                        'dst_port': pkt[TCP].dport,
                        'flags': self._get_tcp_flags(pkt[TCP])
                    }
                    syn_packets.append(connection)
                    
        return syn_packets
        
    def get_established_connections(self):
        """Get established TCP connections (SYN-ACK detected)."""
        established = []
        
        for session_key, packets in self.sessions.items():
            has_syn = False
            has_syn_ack = False
            has_ack = False
            
            for pkt in packets:
                flags = pkt['flags']
                if 'S' in flags and 'A' not in flags:
                    has_syn = True
                elif 'S' in flags and 'A' in flags:
                    has_syn_ack = True
                elif 'A' in flags and 'S' not in flags:
                    has_ack = True
                    
            if has_syn and has_syn_ack and has_ack:
                src_ip, src_port, dst_ip, dst_port = session_key
                established.append({
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'packet_count': len(packets),
                    'total_bytes': sum(p['payload_size'] for p in packets)
                })
                
        return established
        
    def get_session_summary(self, session_key):
        """Get summary statistics for a specific session."""
        packets = self.sessions.get(session_key, [])
        if not packets:
            return None
            
        src_to_dst_bytes = 0
        dst_to_src_bytes = 0
        
        for pkt in packets:
            if (pkt['src_ip'], pkt['src_port']) == (session_key[0], session_key[1]):
                src_to_dst_bytes += pkt['payload_size']
            else:
                dst_to_src_bytes += pkt['payload_size']
                
        return {
            'session_key': session_key,
            'packet_count': len(packets),
            'src_to_dst_bytes': src_to_dst_bytes,
            'dst_to_src_bytes': dst_to_src_bytes,
            'total_bytes': src_to_dst_bytes + dst_to_src_bytes,
            'duration': packets[-1]['timestamp'] - packets[0]['timestamp'] if len(packets) > 1 else 0
        }
        
    def get_top_sessions_by_volume(self, n=10):
        """Get top N sessions by data volume."""
        sessions_with_volume = []
        
        for session_key in self.sessions:
            summary = self.get_session_summary(session_key)
            if summary:
                sessions_with_volume.append(summary)
                
        return sorted(sessions_with_volume, key=lambda x: x['total_bytes'], reverse=True)[:n]
        
    def get_connections_by_ip(self, ip):
        """Get all connections involving a specific IP."""
        connections = []
        
        for session_key, packets in self.sessions.items():
            if ip in session_key[:3:2]:  # Check src_ip and dst_ip
                summary = self.get_session_summary(session_key)
                if summary:
                    connections.append(summary)
                    
        return connections
        
    def get_port_distribution(self):
        """Get distribution of destination ports."""
        ports = defaultdict(int)
        
        for pkt in self.packets:
            if TCP in pkt:
                ports[pkt[TCP].dport] += 1
                
        return dict(sorted(ports.items(), key=lambda x: x[1], reverse=True))
        
    @staticmethod
    def _get_tcp_flags(tcp_layer):
        """Convert TCP flags to string representation."""
        flags = []
        if tcp_layer.flags & 0x01:  # FIN
            flags.append('F')
        if tcp_layer.flags & 0x02:  # SYN
            flags.append('S')
        if tcp_layer.flags & 0x04:  # RST
            flags.append('R')
        if tcp_layer.flags & 0x08:  # PSH
            flags.append('P')
        if tcp_layer.flags & 0x10:  # ACK
            flags.append('A')
        if tcp_layer.flags & 0x20:  # URG
            flags.append('U')
            
        return ''.join(flags) if flags else 'None'
