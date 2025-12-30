"""Configuration and constants for NPI."""

# Whitelisted domains (known legitimate services)
# Whitelisted domains (known legitimate services)
WHITELISTED_DOMAINS = [
    # Google
    'google.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com',
    'googlevideo.com', 'youtube.com', 'ytimg.com', 'ggpht.com',
    
    # Microsoft
    'microsoft.com', 'msftconnecttest.com', 'live.com', 'windowsupdate.com',
    'bing.com', 'msn.com', 'office.com', 'office365.com', 'outlook.com',
    'windows.com', 'azure.com', 'visualstudio.com',
    
    # Apple
    'apple.com', 'icloud.com', 'apple-dns.net',
    
    # CDNs
    'cloudflare.com', 'akamai.net', 'fastly.net', 'cloudfront.net',
    
    # AWS
    'amazon.com', 'amazonaws.com', 'aws.com',
    
    # Other common
    'php.net', 'python.org', 'github.com', 'stackoverflow.com'
]

# Suspicious indicators
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work']
KNOWN_MALICIOUS_PORTS = [4444, 5555, 6666, 6667, 31337, 12345, 54321]
KNOWN_C2_PORTS = [8080, 8443, 4443, 8888]

# Thresholds (ADJUSTED FOR BETTER DETECTION)
DNS_ENTROPY_THRESHOLD = 3.5  # Lowered to catch more DGA domains
DNS_SUBDOMAIN_THRESHOLD = 5  # Lowered to detect tunneling
HTTP_UPLOAD_THRESHOLD = 1024 * 1024  # 1MB
TCP_CONNECTION_THRESHOLD = 100
DATA_EXFIL_THRESHOLD = 5 * 1024 * 1024  # 5MB (lowered from 10MB)

# DNS Tunneling detection (LOWERED THRESHOLDS)
DNS_QUERY_LENGTH_THRESHOLD = 30  # Lowered from 50 to catch more tunneling
DNS_QUERIES_PER_DOMAIN_THRESHOLD = 10  # Lowered from 20

# HTTP patterns
SUSPICIOUS_USER_AGENTS = [
    'python-requests',
    'curl',
    'wget',
    'powershell',
    'Empire',
    'Metasploit',
    'Cobalt Strike'
]

SUSPICIOUS_PATHS = [
    '/shell',
    '/cmd',
    '/admin/upload',
    '/phpMyAdmin',
    '/wp-admin',
    '.php',
    '.asp',
    '.jsp'
]

# Suspicious but legitimate paths (don't flag as malicious)
LEGITIMATE_SUSPICIOUS_PATHS = [
    '/din.aspx',  # TeamViewer DynGate
    '/dout.aspx', # TeamViewer DynGate
]

# Remote access tools (flag separately)
REMOTE_ACCESS_TOOLS = [
    'teamviewer.com',
    'logmein.com',
    'anydesk.com',
    'ammyy.com',
    'ultraviewer.net'
    'netsupportsoftware.com',  # Added - commonly abused as RAT
]

# Colors for terminal output
class Colors:
    CRITICAL = '\033[91m'  # Red
    WARNING = '\033[93m'   # Yellow
    INFO = '\033[94m'      # Blue
    SUCCESS = '\033[92m'   # Green
    RESET = '\033[0m'      # Reset
