"""HTTP traffic analyzer for detecting suspicious activities."""

from collections import defaultdict
import re
from utils.config import (
    SUSPICIOUS_USER_AGENTS,
    SUSPICIOUS_PATHS,
    HTTP_UPLOAD_THRESHOLD,
    REMOTE_ACCESS_TOOLS
)


class HTTPAnalyzer:
    """Analyze HTTP traffic for suspicious patterns."""
    
    def __init__(self, http_parser, reporter):
        self.http_parser = http_parser
        self.reporter = reporter
        self._reported_remote_access = set()
        
    def analyze(self):
        """Run all HTTP analysis checks."""
        print("[*] Analyzing HTTP traffic...")
        
        self.detect_suspicious_user_agents()
        self.detect_suspicious_paths()
        self.detect_large_uploads()
        
    def detect_suspicious_user_agents(self):
        """Detect automated tools and suspicious user agents."""
        for request in self.http_parser.requests:
            user_agent = request.get('user_agent', '').lower()
            
            for suspicious_ua in SUSPICIOUS_USER_AGENTS:
                if suspicious_ua.lower() in user_agent:
                    self.reporter.print_finding(
                        'WARNING',
                        'Suspicious User-Agent',
                        f'Automated/suspicious user agent detected',
                        {
                            'User-Agent': request.get('user_agent', 'Unknown'),
                            'Source IP': request['src_ip'],
                            'Destination': f"{request['host']}{request['path']}",
                            'Method': request['method']
                        }
                    )
                    break
                    
    def detect_suspicious_paths(self):
        """Detect requests to suspicious paths."""
        reported_paths = {}  # Track reported path+host combinations
        
        for request in self.http_parser.requests:
            path = request['path'].lower()
            host = request['host'].lower()
            
            # Check for remote access tools first
            for rat in REMOTE_ACCESS_TOOLS:
                if rat in host:
                    if host not in self._reported_remote_access:
                        self._reported_remote_access.add(host)
                        self.reporter.print_finding(
                            'INFO',
                            'Remote Access Tool Usage',
                            f'Remote access tool activity detected',
                            {
                                'Tool': host,
                                'Source IP': request['src_ip'],
                                'Requests': 'Multiple',
                                'Note': 'May be legitimate or malicious'
                            }
                        )
                    return  # Don't flag paths for known remote access tools
            
            # Check for suspicious paths
            for suspicious_path in SUSPICIOUS_PATHS:
                if suspicious_path.lower() in path:
                    # Create unique key for this path+host combination
                    path_key = (host, path)
                    
                    # If not already reported, track it
                    if path_key not in reported_paths:
                        reported_paths[path_key] = {
                            'count': 1,
                            'src_ips': {request['src_ip']},
                            'methods': {request['method']},
                            'request': request
                        }
                    else:
                        # Update existing entry
                        reported_paths[path_key]['count'] += 1
                        reported_paths[path_key]['src_ips'].add(request['src_ip'])
                        reported_paths[path_key]['methods'].add(request['method'])
                    
                    break
        
        # Report deduplicated suspicious paths
        for (host, path), info in reported_paths.items():
            # Skip if already covered by C2 beaconing detection (more than 10 requests)
            if info['count'] > 10:
                continue
                
            self.reporter.print_finding(
                'WARNING',
                'Suspicious Path Access',
                f'Request(s) to suspicious path detected',
                {
                    'Path': path,
                    'Host': host,
                    'Request Count': info['count'] if info['count'] > 1 else None,
                    'Source IPs': ', '.join(info['src_ips']),
                    'Methods': ', '.join(info['methods'])
                }
            )
                    
    def detect_large_uploads(self):
        """Detect unusually large POST/PUT requests and C2 beaconing."""
        upload_methods = ['POST', 'PUT']
        
        # Track POST requests to same destination
        post_destinations = defaultdict(list)
        
        for request in self.http_parser.requests:
            method = request['method']
            content_length = request.get('content_length', 0)
            
            # Track multiple POSTs to same destination
            if method == 'POST':
                dest = f"{request['host']}{request['path']}"
                post_destinations[dest].append(request)
            
            # Detect large uploads
            if method in upload_methods and content_length > HTTP_UPLOAD_THRESHOLD:
                self.reporter.print_finding(
                    'WARNING',
                    'Large Upload Detected',
                    f'Large {method} request detected',
                    {
                        'Destination': f"{request['host']}{request['path']}",
                        'Size': f'{content_length / (1024*1024):.2f} MB',
                        'Source IP': request['src_ip'],
                        'Method': method
                    }
                )
        
        # Check for excessive POST requests (C2 beaconing detection)
        for dest, requests in post_destinations.items():
            if len(requests) <= 10:
                continue
                
            # Check if host is an IP address (more suspicious)
            host = requests[0]['host']
            is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host)
            
            # Check for suspicious patterns in URL
            suspicious_patterns = ['fake', 'test', 'tmp', 'temp', 'data', 'upload']
            is_suspicious_path = any(pattern in dest.lower() for pattern in suspicious_patterns)
            
            # Only report if suspicious indicators present
            if not (is_ip or is_suspicious_path or len(requests) > 50):
                continue
            
            # Get unique source IPs
            src_ips = list(set(req['src_ip'] for req in requests))
            
            # Build indicators list
            indicators = []
            if is_ip:
                indicators.append('Direct IP communication')
            if is_suspicious_path:
                indicators.append('Suspicious path')
            if len(requests) > 50:
                indicators.append('High volume')
            
            self.reporter.print_finding(
                'CRITICAL',
                'Potential C2 Beaconing',
                'High volume of POST requests to suspicious endpoint',
                {
                    'Destination': dest,
                    'Request Count': len(requests),
                    'Source IPs': ', '.join(src_ips),
                    'Suspicious Indicators': ', '.join(indicators)
                }
            )
