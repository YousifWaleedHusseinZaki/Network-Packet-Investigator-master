"""HTTP packet parser and extractor."""

from scapy.all import TCP, Raw, IP
from collections import defaultdict
import re


class HTTPParser:
    """Extract and analyze HTTP requests and responses."""
    
    def __init__(self, packets):
        self.packets = packets
        self.requests = []
        self.responses = []
        self.methods = defaultdict(int)
        
    def extract_requests(self):
        """Extract HTTP requests from packets."""
        for pkt in self.packets:
            if TCP in pkt and Raw in pkt:
                payload = pkt[Raw].load
                
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    
                    # Check if it's an HTTP request
                    if any(method in payload_str[:10] for method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']):
                        request = self._parse_http_request(pkt, payload_str)
                        if request:
                            self.requests.append(request)
                            self.methods[request['method']] += 1
                except Exception:
                    continue
                    
        return self.requests
        
    def _parse_http_request(self, pkt, payload):
        """Parse HTTP request details."""
        lines = payload.split('\r\n')
        if not lines:
            return None
            
        # Parse request line
        request_line = lines[0].split(' ')
        if len(request_line) < 3:
            return None
            
        method, path, version = request_line[0], request_line[1], request_line[2]
        
        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
                
        request = {
            'timestamp': float(pkt.time),
            'src_ip': pkt[IP].src if IP in pkt else None,
            'dst_ip': pkt[IP].dst if IP in pkt else None,
            'src_port': pkt[TCP].sport,
            'dst_port': pkt[TCP].dport,
            'method': method,
            'path': path,
            'version': version,
            'host': headers.get('Host', ''),
            'user_agent': headers.get('User-Agent', ''),
            'content_length': int(headers.get('Content-Length', 0)),
            'headers': headers,
            'payload_size': len(payload)
        }
        
        return request
        
    def extract_responses(self):
        """Extract HTTP responses from packets."""
        for pkt in self.packets:
            if TCP in pkt and Raw in pkt:
                payload = pkt[Raw].load
                
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    
                    # Check if it's an HTTP response
                    if payload_str.startswith('HTTP/'):
                        response = self._parse_http_response(pkt, payload_str)
                        if response:
                            self.responses.append(response)
                except Exception:
                    continue
                    
        return self.responses
        
    def _parse_http_response(self, pkt, payload):
        """Parse HTTP response details."""
        lines = payload.split('\r\n')
        if not lines:
            return None
            
        # Parse status line
        status_line = lines[0].split(' ', 2)
        if len(status_line) < 2:
            return None
            
        version, status_code = status_line[0], status_line[1]
        status_message = status_line[2] if len(status_line) > 2 else ''
        
        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
                
        response = {
            'timestamp': float(pkt.time),
            'src_ip': pkt[IP].src if IP in pkt else None,
            'dst_ip': pkt[IP].dst if IP in pkt else None,
            'version': version,
            'status_code': status_code,
            'status_message': status_message,
            'content_length': int(headers.get('Content-Length', 0)),
            'content_type': headers.get('Content-Type', ''),
            'headers': headers,
            'payload_size': len(payload)
        }
        
        return response
        
    def get_requests_by_method(self, method):
        """Get all requests with specific HTTP method."""
        return [r for r in self.requests if r['method'] == method]
        
    def get_method_distribution(self):
        """Get distribution of HTTP methods."""
        return dict(self.methods)
