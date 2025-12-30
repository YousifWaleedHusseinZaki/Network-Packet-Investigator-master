"""Main PCAP file parser with better format support."""

from scapy.all import rdpcap, PcapReader, IP, TCP, UDP, ICMP, DNS, Raw
from collections import defaultdict
import os


class PcapParser:
    """Parse PCAP files and extract packet information."""
    
    def __init__(self, pcap_file):
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
            
        self.pcap_file = pcap_file
        self.packets = []
        self.stats = defaultdict(int)
        
    def load(self):
        """Load PCAP file into memory."""
        print(f"Loading PCAP file: {self.pcap_file}")
        
        try:
            # Try standard rdpcap first
            self.packets = rdpcap(self.pcap_file)
        except Exception as e:
            # Try with PcapReader for better format support
            try:
                print(f"Trying alternative reader...")
                with PcapReader(self.pcap_file) as reader:
                    self.packets = [pkt for pkt in reader]
            except Exception as e2:
                # Try reading with tcpdump conversion
                print(f"Error: {e}")
                print(f"Alternative error: {e2}")
                print("\nTip: Try converting the file first:")
                print(f"  tshark -r {self.pcap_file} -w converted.pcap")
                print(f"  tcpdump -r {self.pcap_file} -w converted.pcap")
                raise
        
        # Filter out non-IP packets
        ip_packets = [pkt for pkt in self.packets if IP in pkt]
        
        if len(ip_packets) == 0 and len(self.packets) > 0:
            print(f"WARNING: Found {len(self.packets)} packets but 0 IP packets")
            print("This file may have unusual encapsulation or be corrupted")
            print("\nTrying to salvage data...")
            # Keep all packets for further inspection
        else:
            self.packets = ip_packets
            
        print(f"Loaded {len(self.packets)} packets\n")
        return self.packets
        
    def get_basic_stats(self):
        """Get basic statistics about the PCAP."""
        for pkt in self.packets:
            if IP in pkt:
                self.stats['ip_packets'] += 1
                
                if TCP in pkt:
                    self.stats['tcp_packets'] += 1
                    
                    # Check for HTTP
                    if Raw in pkt:
                        try:
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                            if any(x in payload[:20] for x in ['GET', 'POST', 'HTTP']):
                                self.stats['http_packets'] += 1
                        except:
                            pass
                            
                elif UDP in pkt:
                    self.stats['udp_packets'] += 1
                elif ICMP in pkt:
                    self.stats['icmp_packets'] += 1
                    
                if DNS in pkt:
                    self.stats['dns_packets'] += 1
                    
        return dict(self.stats)
        
    def get_conversations(self):
        """Extract unique IP conversations."""
        conversations = set()
        
        for pkt in self.packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                conv = tuple(sorted([src, dst]))
                conversations.add(conv)
                
        return list(conversations)
        
    def get_ip_pairs(self):
        """Get all source-destination IP pairs with counts."""
        pairs = defaultdict(int)
        
        for pkt in self.packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                pairs[(src, dst)] += 1
                
        return dict(pairs)
