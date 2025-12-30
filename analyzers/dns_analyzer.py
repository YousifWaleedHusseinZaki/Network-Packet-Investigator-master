"""DNS traffic analyzer for detecting anomalies and threats."""

import math
from collections import Counter
import tldextract
from utils.config import (
    DNS_ENTROPY_THRESHOLD,
    DNS_SUBDOMAIN_THRESHOLD,
    DNS_QUERY_LENGTH_THRESHOLD,
    DNS_QUERIES_PER_DOMAIN_THRESHOLD,
    SUSPICIOUS_TLDS,
    WHITELISTED_DOMAINS
)


class DNSAnalyzer:
    """Analyze DNS traffic for suspicious patterns."""
    
    def __init__(self, dns_parser, reporter):
        self.dns_parser = dns_parser
        self.reporter = reporter
        self.reported_domains = set()
        
    def analyze(self):
        """Run all DNS analysis checks."""
        print("[*] Analyzing DNS traffic...")
        
        self.detect_dga_domains()
        self.detect_dns_tunneling()
        self.detect_suspicious_tlds()
        self.detect_excessive_subdomains()
        self.detect_high_query_volume()
        self.detect_dns_shell()  # NEW: Detect DNS-based remote shells
        
    def _is_whitelisted(self, domain):
        """Check if domain is whitelisted."""
        domain = domain.lower().rstrip('.')
        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        subdomain = extracted.subdomain.upper()
        
        # Skip internal/corporate/AD domains - EXPANDED LIST
        internal_patterns = [
            '_ldap', '_tcp', '_udp', '_msdcs', '_kerberos', '_sites',
            'default-first-site-name', 'forestdnszones', 'domaindnszones',
            'wpad', '.local', '.lan', '.corp', '.internal',
            'desktop-', 'win-', 'pc-', 'laptop-', 'srv-', 'dc-', '-dc'  # Added -dc
        ]

        if any(pattern in domain for pattern in internal_patterns):
            return True

        # Skip corporate TLDs for domain controllers
        if subdomain and ('-dc' in subdomain or 'dc-' in subdomain):
            corporate_tlds = ['.health', '.local', '.corp', '.internal']
            if any(tld in domain for tld in corporate_tlds):
                return True

        
        # Skip Azure/cloud service hashes (legitimate)
        if 'footprintdns.com' in domain or 'azureedge.net' in domain:
            return True
        
        # Check against whitelist
        for whitelisted in WHITELISTED_DOMAINS:
            if base_domain.endswith(whitelisted) or domain.endswith(whitelisted):
                return True
        
        return False
        
    def detect_dga_domains(self):
        """Detect algorithmically generated domains using entropy."""
        for query in self.dns_parser.queries:
            domain = query['query'].rstrip('.')
            
            # Skip if already reported
            if domain in self.reported_domains:
                continue
                
            # Skip whitelisted domains (includes AD)
            if self._is_whitelisted(domain):
                continue
            
            extracted = tldextract.extract(domain)
            subdomain_part = extracted.subdomain + extracted.domain
            
            if subdomain_part:
                entropy = self._calculate_entropy(subdomain_part)
                
                if entropy > DNS_ENTROPY_THRESHOLD:
                    self.reported_domains.add(domain)
                    self.reporter.print_finding(
                        'WARNING',
                        'Potential DGA Domain',
                        f'High entropy domain detected: {domain}',
                        {
                            'Domain': domain,
                            'Entropy': f'{entropy:.2f}',
                            'Source IP': query['src_ip'],
                            'Threshold': DNS_ENTROPY_THRESHOLD
                        }
                    )
                    
    def detect_dns_tunneling(self):
        """Detect DNS tunneling based on query characteristics."""
        long_queries = []
        
        for query in self.dns_parser.queries:
            domain = query['query']
            
            # Skip whitelisted domains (ADDED)
            if self._is_whitelisted(domain):
                continue
            
            # Check for unusually long queries
            if len(domain) > DNS_QUERY_LENGTH_THRESHOLD:
                long_queries.append(query)
                
        if long_queries:
            # Group by source IP
            by_src = {}
            for q in long_queries:
                src = q['src_ip']
                if src not in by_src:
                    by_src[src] = []
                by_src[src].append(q)
                
            for src_ip, queries in by_src.items():
                if len(queries) > 5:
                    self.reporter.print_finding(
                        'CRITICAL',
                        'Potential DNS Tunneling',
                        f'Multiple long DNS queries detected from {src_ip}',
                        {
                            'Source IP': src_ip,
                            'Query Count': len(queries),
                            'Average Length': sum(len(q['query']) for q in queries) // len(queries),
                            'Sample Query': queries[0]['query'][:50] + '...'
                        }
                    )
                    
    def detect_suspicious_tlds(self):
        """Detect queries to suspicious top-level domains."""
        reported_tlds = set()
        
        for query in self.dns_parser.queries:
            domain = query['query']
            
            # Skip whitelisted
            if self._is_whitelisted(domain):
                continue
            
            for suspicious_tld in SUSPICIOUS_TLDS:
                tld_key = (domain, suspicious_tld)
                if domain.endswith(suspicious_tld) and tld_key not in reported_tlds:
                    reported_tlds.add(tld_key)
                    self.reporter.print_finding(
                        'WARNING',
                        'Suspicious TLD',
                        f'Query to suspicious TLD detected: {domain}',
                        {
                            'Domain': domain,
                            'TLD': suspicious_tld,
                            'Source IP': query['src_ip']
                        }
                    )
                    break
                    
    def detect_excessive_subdomains(self):
        """Detect domains with excessive unique subdomains."""
        domain_subdomains = {}
        
        for query in self.dns_parser.queries:
            domain = query['query'].rstrip('.')
            
            # Skip whitelisted (ADDED)
            if self._is_whitelisted(domain):
                continue
            
            extracted = tldextract.extract(domain)
            base_domain = f"{extracted.domain}.{extracted.suffix}"
            full_domain = domain
            
            if base_domain not in domain_subdomains:
                domain_subdomains[base_domain] = set()
            domain_subdomains[base_domain].add(full_domain)
            
        for base_domain, subdomains in domain_subdomains.items():
            # Skip whitelisted
            if self._is_whitelisted(base_domain):
                continue
                
            if len(subdomains) > DNS_SUBDOMAIN_THRESHOLD:
                self.reporter.print_finding(
                    'WARNING',
                    'Excessive Subdomains',
                    f'Domain with many unique subdomains: {base_domain}',
                    {
                        'Base Domain': base_domain,
                        'Unique Subdomains': len(subdomains),
                        'Threshold': DNS_SUBDOMAIN_THRESHOLD
                    }
                )
                
    def detect_high_query_volume(self):
        """Detect domains with unusually high query volume."""
        top_domains = self.dns_parser.get_top_domains(5)
        
        for domain, count in top_domains:
            # Skip whitelisted
            if self._is_whitelisted(domain):
                continue
                
            if count > DNS_QUERIES_PER_DOMAIN_THRESHOLD:
                self.reporter.print_finding(
                    'INFO',
                    'High Query Volume',
                    f'Domain queried frequently: {domain}',
                    {
                        'Domain': domain,
                        'Query Count': count,
                        'Threshold': DNS_QUERIES_PER_DOMAIN_THRESHOLD
                    }
                )
                
    @staticmethod
    def _calculate_entropy(string):
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0
            
        entropy = 0
        for count in Counter(string).values():
            probability = count / len(string)
            entropy -= probability * math.log2(probability)
            
        return entropy

    def detect_dns_shell(self):
        """Detect DNS-based remote shells and command execution."""
        import re
        from collections import defaultdict
        
        # Track suspicious patterns
        txt_queries = []
        suspicious_domains = defaultdict(list)
        
        for query in self.dns_parser.queries:
            domain = query['query'].rstrip('.')
            qtype = query.get('qtype_name', 'A')
            
            # Skip whitelisted
            if self._is_whitelisted(domain):
                continue
            
            # TXT queries are common in DNS shells for command output
            if qtype == 'TXT':
                txt_queries.append(query)
            
            # Look for base64-like patterns in subdomains (command data)
            if re.search(r'[A-Za-z0-9+/=]{10,}', domain):
                suspicious_domains[query['src_ip']].append(domain)
            
            # Look for hex-encoded data
            if re.search(r'[0-9a-fA-F]{16,}', domain):
                suspicious_domains[query['src_ip']].append(domain)
            
            # Look for short repeated subdomain patterns (shell polling)
            parts = domain.split('.')
            if len(parts) > 3 and all(len(p) <= 4 for p in parts[:-2]):
                suspicious_domains[query['src_ip']].append(domain)
        
        # Report TXT query abuse
        if len(txt_queries) > 3:
            by_src = defaultdict(list)
            for q in txt_queries:
                by_src[q['src_ip']].append(q)
            
            for src_ip, queries in by_src.items():
                if len(queries) > 2:
                    self.reporter.print_finding(
                        'CRITICAL',
                        'DNS Remote Shell',
                        f'Suspicious TXT DNS queries detected (possible DNS shell)',
                        {
                            'Source IP': src_ip,
                            'TXT Query Count': len(queries),
                            'Sample Domain': queries[0]['query'][:50],
                            'Detection': 'TXT record abuse for command/data exchange'
                        }
                    )
        
        # Report encoded data in DNS
        for src_ip, domains in suspicious_domains.items():
            if len(domains) > 3:
                self.reporter.print_finding(
                    'CRITICAL',
                    'DNS Data Channel',
                    f'Encoded data detected in DNS queries (possible C2 channel)',
                    {
                        'Source IP': src_ip,
                        'Suspicious Queries': len(domains),
                        'Sample Domain': domains[0][:60],
                        'Detection': 'Base64/Hex encoded data in DNS subdomain'
                    }
                )
