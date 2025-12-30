"""DNS packet parser and extractor."""

from scapy.all import DNS, DNSQR, DNSRR, IP
from collections import defaultdict, Counter


class DNSParser:
    """Extract and analyze DNS queries and responses."""
    
    def __init__(self, packets):
        self.packets = packets
        self.queries = []
        self.responses = []
        self.query_types = Counter()
        self.domains = Counter()
        
    def extract_queries(self):
        """Extract all DNS queries."""
        for pkt in self.packets:
            if DNS in pkt and DNSQR in pkt:
                query = {
                    'timestamp': float(pkt.time),
                    'src_ip': pkt[IP].src if IP in pkt else None,
                    'dst_ip': pkt[IP].dst if IP in pkt else None,
                    'query': pkt[DNSQR].qname.decode('utf-8', errors='ignore'),
                    'qtype': pkt[DNSQR].qtype,
                    'qtype_name': self._get_qtype_name(pkt[DNSQR].qtype)
                }
                self.queries.append(query)
                self.domains[query['query']] += 1
                self.query_types[query['qtype_name']] += 1
                
        return self.queries
        
    def extract_responses(self):
        """Extract all DNS responses."""
        for pkt in self.packets:
            try:
                if DNS in pkt and pkt[DNS].ancount > 0:
                    response = {
                        'timestamp': float(pkt.time),
                        'src_ip': pkt[IP].src if IP in pkt else None,
                        'query': pkt[DNSQR].qname.decode('utf-8', errors='ignore') if DNSQR in pkt else None,
                        'answers': []
                    }
                    
                    # Extract answer records
                    for i in range(pkt[DNS].ancount):
                        try:
                            if pkt[DNS].an and pkt[DNS].an[i]:
                                answer = {
                                    'name': pkt[DNS].an[i].rrname.decode('utf-8', errors='ignore') if hasattr(pkt[DNS].an[i], 'rrname') else '',
                                    'type': pkt[DNS].an[i].type if hasattr(pkt[DNS].an[i], 'type') else 0,
                                    'rdata': str(pkt[DNS].an[i].rdata) if hasattr(pkt[DNS].an[i], 'rdata') else ''
                                }
                                response['answers'].append(answer)
                        except (AttributeError, IndexError) as e:
                            # Skip malformed answer records
                            continue
                            
                    if response['answers']:  # Only add if we got valid answers
                        self.responses.append(response)
            except Exception as e:
                # Skip packets that can't be parsed
                continue
                
        return self.responses
            
    def get_top_domains(self, n=10):
        """Get top N queried domains."""
        return self.domains.most_common(n)
        
    def get_query_type_distribution(self):
        """Get distribution of query types."""
        return dict(self.query_types)
        
    def get_queries_by_domain(self, domain):
        """Get all queries for a specific domain."""
        return [q for q in self.queries if domain in q['query']]
        
    def get_subdomain_count(self, domain):
        """Count unique subdomains for a domain."""
        subdomains = set()
        for q in self.queries:
            if domain in q['query']:
                subdomains.add(q['query'])
        return len(subdomains)
        
    @staticmethod
    def _get_qtype_name(qtype):
        """Convert query type number to name."""
        types = {
            1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
            12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
            33: 'SRV', 255: 'ANY'
        }
        return types.get(qtype, f'TYPE{qtype}')
