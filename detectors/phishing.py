"""Phishing and malicious domain detector."""

import re
from collections import defaultdict
import tldextract


class PhishingDetector:
    """Detect potential phishing activities."""
    
    def __init__(self, dns_parser, http_parser, reporter):
        self.dns_parser = dns_parser
        self.http_parser = http_parser
        self.reporter = reporter
        self.reported_typosquat = set()  # Track reported pairs
        
        # Common legitimate brands that are often spoofed
        self.legitimate_brands = [
            'microsoft', 'google', 'facebook', 'amazon', 'apple',
            'paypal', 'netflix', 'linkedin', 'instagram', 'twitter',
            'dropbox', 'adobe', 'yahoo', 'ebay', 'chase',
            'wellsfargo', 'bankofamerica', 'citibank'
        ]
        
    def analyze(self):
        """Run all phishing detection checks."""
        print("[*] Analyzing for phishing activities...")
        
        self.detect_typosquatting()
        self.detect_homograph_attacks()
        self.detect_suspicious_subdomains()
        self.detect_credential_submission()
        
    def detect_typosquatting(self):
        """Detect domains that are similar to legitimate brands (typosquatting)."""
        for query in self.dns_parser.queries:
            domain = query['query'].rstrip('.').lower()
            extracted = tldextract.extract(domain)
            domain_name = extracted.domain
            
            # Skip if domain is too short
            if len(domain_name) < 4:
                continue
            
            for brand in self.legitimate_brands:
                # Skip if it's actually the legitimate domain
                if domain_name == brand:
                    continue
                
                # Skip if already reported this combination
                pair_key = (domain, brand)
                if pair_key in self.reported_typosquat:
                    continue
                
                # More strict typosquatting check
                if self._is_typosquat_strict(domain_name, brand):
                    self.reported_typosquat.add(pair_key)
                    self.reporter.print_finding(
                        'WARNING',
                        'Potential Typosquatting',
                        f'Domain similar to legitimate brand detected',
                        {
                            'Queried Domain': domain,
                            'Similar To': brand,
                            'Source IP': query['src_ip'],
                            'Match Type': self._get_match_type(domain_name, brand)
                        }
                    )
                        
    def detect_homograph_attacks(self):
        """Detect IDN homograph attacks (lookalike characters)."""
        seen_domains = set()
        
        for query in self.dns_parser.queries:
            domain = query['query'].rstrip('.')
            
            if domain in seen_domains:
                continue
            seen_domains.add(domain)
            
            # Check if domain contains non-ASCII characters
            if not domain.isascii():
                self.reporter.print_finding(
                    'WARNING',
                    'IDN Homograph Attack',
                    f'Domain with non-ASCII characters detected',
                    {
                        'Domain': domain,
                        'Source IP': query['src_ip'],
                        'Description': 'Possible homograph/lookalike attack'
                    }
                )
                
    def detect_suspicious_subdomains(self):
        """Detect suspicious subdomain patterns."""
        suspicious_keywords = [
            'login', 'signin', 'account', 'verify', 'secure',
            'update', 'confirm', 'banking', 'wallet', 'payment'
        ]
        
        seen_combos = set()
        
        for query in self.dns_parser.queries:
            domain = query['query'].rstrip('.').lower()
            extracted = tldextract.extract(domain)
            subdomain = extracted.subdomain
            
            # Check for suspicious keywords in subdomain
            for keyword in suspicious_keywords:
                if keyword in subdomain:
                    # Check if it's a brand domain
                    domain_name = extracted.domain
                    for brand in self.legitimate_brands:
                        combo_key = (domain, brand, keyword)
                        if brand in subdomain and brand != domain_name and combo_key not in seen_combos:
                            seen_combos.add(combo_key)
                            self.reporter.print_finding(
                                'WARNING',
                                'Suspicious Subdomain',
                                f'Subdomain mimicking legitimate service',
                                {
                                    'Full Domain': domain,
                                    'Subdomain': subdomain,
                                    'Keyword': keyword,
                                    'Potential Target': brand,
                                    'Source IP': query['src_ip']
                                }
                            )
                            break
                            
    def detect_credential_submission(self):
        """Detect potential credential submission (POST to login forms)."""
        login_keywords = ['login', 'signin', 'auth', 'password', 'credential']
        
        for request in self.http_parser.requests:
            if request['method'] == 'POST':
                path = request['path'].lower()
                host = request['host'].lower()
                
                # Check if path contains login-related keywords
                for keyword in login_keywords:
                    if keyword in path or keyword in host:
                        self.reporter.print_finding(
                            'INFO',
                            'Credential Submission',
                            f'POST request to authentication endpoint',
                            {
                                'Destination': f"{request['host']}{request['path']}",
                                'Source IP': request['src_ip'],
                                'Content Length': request.get('content_length', 0),
                                'Keyword': keyword
                            }
                        )
                        break
    
    @staticmethod
    def _is_typosquat_strict(domain, brand):
        """Strict typosquatting check - requires close match."""
        # Must be similar length
        if abs(len(domain) - len(brand)) > 3:
            return False
        
        # Check for common typosquatting patterns
        # 1. Character substitution (e.g., paypai, g00gle)
        if domain.replace('0', 'o').replace('1', 'l').replace('5', 's') == brand:
            return True
        
        # 2. Single character insertion/deletion
        if len(domain) == len(brand) + 1:
            for i in range(len(domain)):
                if domain[:i] + domain[i+1:] == brand:
                    return True
        
        # 3. Single character change (but not substring match)
        if len(domain) == len(brand):
            differences = sum(1 for a, b in zip(domain, brand) if a != b)
            if differences == 1:
                return True
        
        # 4. Transposition (e.g., googel)
        if len(domain) == len(brand):
            for i in range(len(domain) - 1):
                swapped = list(domain)
                swapped[i], swapped[i+1] = swapped[i+1], swapped[i]
                if ''.join(swapped) == brand:
                    return True
        
        return False
    
    @staticmethod
    def _get_match_type(domain, brand):
        """Determine how the domain matches the brand."""
        if domain.replace('0', 'o').replace('1', 'l').replace('5', 's') == brand:
            return "Character substitution"
        elif abs(len(domain) - len(brand)) == 1:
            return "Single char insertion/deletion"
        else:
            return "Character transposition"
