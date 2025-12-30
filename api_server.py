#!/usr/bin/env python3
"""Flask REST API Server for Network Packet Investigator."""

import os
import sys
import uuid
import json
import traceback
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers.pcap_parser import PcapParser
from parsers.dns_parser import DNSParser
from parsers.http_parser import HTTPParser
from parsers.tcp_parser import TCPParser
from analyzers.dns_analyzer import DNSAnalyzer
from analyzers.http_analyzer import HTTPAnalyzer
from analyzers.traffic_analyzer import TrafficAnalyzer
from detectors.exfiltration import ExfiltrationDetector
from detectors.phishing import PhishingDetector
from detectors.attack_detector import AttackDetector
from live_capture import LiveCapture

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize live capture
live_capture = None

# Configuration
UPLOAD_FOLDER = Path(__file__).parent / 'uploads'
UPLOAD_FOLDER.mkdir(exist_ok=True)
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap', 'dmp', 'etl', 'snoop', 'pkt'}

# In-memory storage for analysis results
analysis_cache = {}

# Cache for pre-parsed packets (for fast pagination)
packets_cache = {}


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


class WebReporter:
    """Reporter that collects findings for JSON output."""
    
    def __init__(self):
        self.findings = []
        
    def add_finding(self, severity, category, description, details=None):
        """Add a finding."""
        finding = {
            'id': str(uuid.uuid4())[:8],
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'category': category,
            'description': description,
            'details': details or {}
        }
        self.findings.append(finding)
        
    def print_finding(self, severity, category, description, details=None):
        """Same as add_finding for compatibility."""
        self.add_finding(severity, category, description, details)
        
    def get_findings(self):
        """Get all findings."""
        return self.findings
    
    def get_summary(self):
        """Get findings summary."""
        return {
            'critical': sum(1 for f in self.findings if f['severity'] == 'CRITICAL'),
            'warning': sum(1 for f in self.findings if f['severity'] == 'WARNING'),
            'info': sum(1 for f in self.findings if f['severity'] == 'INFO'),
            'total': len(self.findings)
        }


def run_analysis(file_path):
    """Run full PCAP analysis and return results."""
    results = {
        'file': os.path.basename(file_path),
        'analyzed_at': datetime.now().isoformat(),
        'stats': {},
        'dns': {'queries': [], 'responses': [], 'top_domains': []},
        'http': {'requests': [], 'responses': [], 'methods': {}},
        'tcp': {'sessions': [], 'top_sessions': [], 'ports': {}},
        'udp': {'packets': []},
        'raw_packets': [],
        'findings': [],
        'summary': {}
    }
    
    try:
        # Initialize reporter
        reporter = WebReporter()
        
        # Parse PCAP
        pcap_parser = PcapParser(file_path)
        packets = pcap_parser.load()
        
        # Get basic statistics
        stats = pcap_parser.get_basic_stats()
        results['stats'] = stats
        results['stats']['total_packets'] = len(packets)
        results['stats']['conversations'] = len(pcap_parser.get_conversations())
        
        # Initialize parsers
        dns_parser = DNSParser(packets)
        http_parser = HTTPParser(packets)
        tcp_parser = TCPParser(packets)
        
        # Extract DNS data
        dns_parser.extract_queries()
        dns_parser.extract_responses()
        results['dns']['queries'] = dns_parser.queries[:100]  # Limit for performance
        results['dns']['responses'] = dns_parser.responses[:100]
        results['dns']['top_domains'] = dns_parser.get_top_domains(10)
        results['dns']['query_types'] = dns_parser.get_query_type_distribution()
        
        # Extract HTTP data
        http_parser.extract_requests()
        http_parser.extract_responses()
        results['http']['requests'] = http_parser.requests[:100]
        results['http']['responses'] = http_parser.responses[:100]
        results['http']['methods'] = http_parser.get_method_distribution()
        
        # Extract TCP data
        tcp_parser.extract_sessions()
        results['tcp']['session_count'] = len(tcp_parser.sessions)
        results['tcp']['top_sessions'] = tcp_parser.get_top_sessions_by_volume(10)
        results['tcp']['ports'] = dict(list(tcp_parser.get_port_distribution().items())[:20])
        results['tcp']['connections'] = tcp_parser.get_connection_attempts()[:50]
        
        # Extract UDP packets (including TFTP, which uses UDP port 69)
        from scapy.all import UDP, IP, Raw
        udp_packets = []
        for pkt in packets[:1000]:  # Increased limit for better visibility
            if UDP in pkt and IP in pkt:
                udp_pkt = {
                    'timestamp': float(pkt.time),
                    'src_ip': pkt[IP].src,
                    'dst_ip': pkt[IP].dst,
                    'src_port': pkt[UDP].sport,
                    'dst_port': pkt[UDP].dport,
                    'length': len(pkt[UDP]),
                    'payload': '',
                    'protocol': 'UDP'
                }
                # Detect specific UDP protocols
                if pkt[UDP].sport == 69 or pkt[UDP].dport == 69:
                    udp_pkt['protocol'] = 'TFTP'
                elif pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
                    udp_pkt['protocol'] = 'DNS'
                elif pkt[UDP].sport == 67 or pkt[UDP].dport == 67 or pkt[UDP].sport == 68 or pkt[UDP].dport == 68:
                    udp_pkt['protocol'] = 'DHCP'
                elif pkt[UDP].sport == 123 or pkt[UDP].dport == 123:
                    udp_pkt['protocol'] = 'NTP'
                elif pkt[UDP].sport == 161 or pkt[UDP].dport == 161:
                    udp_pkt['protocol'] = 'SNMP'
                
                # Extract payload
                if Raw in pkt:
                    try:
                        payload_bytes = bytes(pkt[Raw].load)
                        # Try to decode as text, otherwise show hex
                        try:
                            udp_pkt['payload'] = payload_bytes.decode('utf-8', errors='replace')[:500]
                        except:
                            udp_pkt['payload'] = payload_bytes.hex()[:500]
                        udp_pkt['payload_size'] = len(payload_bytes)
                    except:
                        udp_pkt['payload'] = ''
                        udp_pkt['payload_size'] = 0
                        
                udp_packets.append(udp_pkt)
        results['udp']['packets'] = udp_packets
        
        # Extract ALL raw packets for complete visibility
        from scapy.all import TCP, ICMP
        raw_packets = []
        for i, pkt in enumerate(packets[:1000]):  # Increased limit for better visibility
            if IP in pkt:
                raw_pkt = {
                    'index': i,
                    'timestamp': float(pkt.time),
                    'src_ip': pkt[IP].src,
                    'dst_ip': pkt[IP].dst,
                    'protocol': 'IP',
                    'length': len(pkt),
                    'info': '',
                    'payload': ''
                }
                
                # Determine protocol
                if TCP in pkt:
                    raw_pkt['protocol'] = 'TCP'
                    raw_pkt['src_port'] = pkt[TCP].sport
                    raw_pkt['dst_port'] = pkt[TCP].dport
                    raw_pkt['info'] = f"TCP {pkt[TCP].sport} → {pkt[TCP].dport}"
                elif UDP in pkt:
                    raw_pkt['protocol'] = 'UDP'
                    raw_pkt['src_port'] = pkt[UDP].sport
                    raw_pkt['dst_port'] = pkt[UDP].dport
                    # Check for TFTP
                    if pkt[UDP].sport == 69 or pkt[UDP].dport == 69:
                        raw_pkt['protocol'] = 'TFTP'
                    raw_pkt['info'] = f"UDP {pkt[UDP].sport} → {pkt[UDP].dport}"
                elif ICMP in pkt:
                    raw_pkt['protocol'] = 'ICMP'
                    raw_pkt['info'] = f"ICMP Type {pkt[ICMP].type}"
                else:
                    raw_pkt['info'] = 'IP Packet'
                
                # Extract payload
                if Raw in pkt:
                    try:
                        payload_bytes = bytes(pkt[Raw].load)
                        try:
                            raw_pkt['payload'] = payload_bytes.decode('utf-8', errors='replace')[:500]
                        except:
                            raw_pkt['payload'] = payload_bytes.hex()[:500]
                        raw_pkt['payload_size'] = len(payload_bytes)
                    except:
                        raw_pkt['payload'] = ''
                        raw_pkt['payload_size'] = 0
                        
                raw_packets.append(raw_pkt)
        results['raw_packets'] = raw_packets
        
        # Run DNS analysis
        dns_analyzer = DNSAnalyzer(dns_parser, reporter)
        dns_analyzer.analyze()
        
        # Run HTTP analysis
        http_analyzer = HTTPAnalyzer(http_parser, reporter)
        http_analyzer.analyze()
        
        # Run traffic analysis
        traffic_analyzer = TrafficAnalyzer(pcap_parser, tcp_parser, reporter)
        traffic_analyzer.analyze()
        
        # Run exfiltration detection
        exfil_detector = ExfiltrationDetector(
            pcap_parser, tcp_parser, http_parser, dns_parser, reporter
        )
        exfil_detector.analyze()
        
        # Run phishing detection
        phishing_detector = PhishingDetector(dns_parser, http_parser, reporter)
        phishing_detector.analyze()
        
        # Run comprehensive attack detection
        attack_detector = AttackDetector(
            pcap_parser, tcp_parser, http_parser, dns_parser, reporter
        )
        attack_detector.analyze()
        
        # Collect findings
        results['findings'] = reporter.get_findings()
        results['summary'] = reporter.get_summary()
        results['status'] = 'success'
        
    except Exception as e:
        results['status'] = 'error'
        results['error'] = str(e)
        results['traceback'] = traceback.format_exc()
        
    return results


# Routes
@app.route('/')
def index():
    """Serve the main dashboard."""
    return send_from_directory('frontend', 'index.html')


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload a PCAP file for analysis."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Allowed: pcap, pcapng, cap'}), 400
        
    # Generate unique ID and save file
    file_id = str(uuid.uuid4())[:8]
    filename = secure_filename(file.filename)
    file_path = UPLOAD_FOLDER / f"{file_id}_{filename}"
    file.save(str(file_path))
    
    return jsonify({
        'file_id': file_id,
        'filename': filename,
        'size': os.path.getsize(file_path),
        'message': 'File uploaded successfully'
    })


@app.route('/api/analyze/<file_id>', methods=['GET'])
def analyze_file(file_id):
    """Run analysis on an uploaded PCAP file."""
    # Find the file
    matching_files = list(UPLOAD_FOLDER.glob(f"{file_id}_*"))
    
    if not matching_files:
        return jsonify({'error': 'File not found'}), 404
        
    file_path = matching_files[0]
    
    # Check cache
    if file_id in analysis_cache:
        return jsonify(analysis_cache[file_id])
    
    # Run analysis
    results = run_analysis(str(file_path))
    
    # Cache results
    analysis_cache[file_id] = results
    
    return jsonify(results)


@app.route('/api/stats/<file_id>', methods=['GET'])
def get_stats(file_id):
    """Get packet statistics for a file."""
    if file_id not in analysis_cache:
        return jsonify({'error': 'File not analyzed yet'}), 404
    
    return jsonify({
        'stats': analysis_cache[file_id].get('stats', {}),
        'summary': analysis_cache[file_id].get('summary', {})
    })


@app.route('/api/dns/<file_id>', methods=['GET'])
def get_dns(file_id):
    """Get DNS analysis results."""
    if file_id not in analysis_cache:
        return jsonify({'error': 'File not analyzed yet'}), 404
    
    return jsonify(analysis_cache[file_id].get('dns', {}))


@app.route('/api/http/<file_id>', methods=['GET'])
def get_http(file_id):
    """Get HTTP analysis results."""
    if file_id not in analysis_cache:
        return jsonify({'error': 'File not analyzed yet'}), 404
    
    return jsonify(analysis_cache[file_id].get('http', {}))


@app.route('/api/sessions/<file_id>', methods=['GET'])
def get_sessions(file_id):
    """Get TCP session data."""
    if file_id not in analysis_cache:
        return jsonify({'error': 'File not analyzed yet'}), 404
    
    return jsonify(analysis_cache[file_id].get('tcp', {}))


@app.route('/api/findings/<file_id>', methods=['GET'])
def get_findings(file_id):
    """Get all threat findings."""
    if file_id not in analysis_cache:
        return jsonify({'error': 'File not analyzed yet'}), 404
    
    return jsonify({
        'findings': analysis_cache[file_id].get('findings', []),
        'summary': analysis_cache[file_id].get('summary', {})
    })


@app.route('/api/export/<file_id>/<format>', methods=['GET'])
def export_report(file_id, format):
    """Export analysis report."""
    if file_id not in analysis_cache:
        return jsonify({'error': 'File not analyzed yet'}), 404
    
    results = analysis_cache[file_id]
    
    if format == 'json':
        return jsonify(results)
    elif format == 'csv':
        # Generate CSV for findings
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Timestamp', 'Severity', 'Category', 'Description'])
        
        for finding in results.get('findings', []):
            writer.writerow([
                finding.get('timestamp', ''),
                finding.get('severity', ''),
                finding.get('category', ''),
                finding.get('description', '')
            ])
        
        return output.getvalue(), 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=npi_report_{file_id}.csv'
        }
    else:
        return jsonify({'error': 'Invalid format. Use json or csv'}), 400


@app.route('/api/packets/<file_id>', methods=['GET'])
def get_packets(file_id):
    """Get paginated packets from a PCAP file with caching and sorting."""
    global packets_cache
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
    
    # Find the file
    matching_files = list(UPLOAD_FOLDER.glob(f"{file_id}_*"))
    if not matching_files:
        return jsonify({'error': 'File not found'}), 404
    
    file_path = matching_files[0]
    
    # Get parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    per_page = min(per_page, 100)  # Max 100 per page
    sort_field = request.args.get('sort', 'timestamp')
    sort_order = request.args.get('order', 'asc')
    
    try:
        # Check cache first
        if file_id not in packets_cache:
            print(f"[*] Parsing packets for {file_id}...")
            packets = rdpcap(str(file_path))
            
            # Pre-parse ALL packets into dictionaries (one-time cost)
            all_packets = []
            for i, pkt in enumerate(packets):
                if IP in pkt:
                    pkt_data = {
                        'index': i + 1,
                        'timestamp': float(pkt.time),
                        'src_ip': pkt[IP].src,
                        'dst_ip': pkt[IP].dst,
                        'protocol': 'IP',
                        'length': len(pkt),
                        'src_port': None,
                        'dst_port': None,
                        'payload': '',
                        'payload_size': 0
                    }
                    
                    # Determine protocol
                    if TCP in pkt:
                        pkt_data['protocol'] = 'TCP'
                        pkt_data['src_port'] = pkt[TCP].sport
                        pkt_data['dst_port'] = pkt[TCP].dport
                    elif UDP in pkt:
                        pkt_data['protocol'] = 'UDP'
                        pkt_data['src_port'] = pkt[UDP].sport
                        pkt_data['dst_port'] = pkt[UDP].dport
                        if pkt[UDP].sport == 69 or pkt[UDP].dport == 69:
                            pkt_data['protocol'] = 'TFTP'
                        elif pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
                            pkt_data['protocol'] = 'DNS'
                    elif ICMP in pkt:
                        pkt_data['protocol'] = 'ICMP'
                    
                    # Extract payload (limited)
                    if Raw in pkt:
                        try:
                            payload_bytes = bytes(pkt[Raw].load)[:200]
                            pkt_data['payload_size'] = len(pkt[Raw].load)
                            try:
                                pkt_data['payload'] = payload_bytes.decode('utf-8', errors='replace')
                            except:
                                pkt_data['payload'] = payload_bytes.hex()
                        except:
                            pass
                    
                    all_packets.append(pkt_data)
            
            packets_cache[file_id] = all_packets
            print(f"[+] Cached {len(all_packets)} packets for {file_id}")
        
        # Get cached packets
        all_packets = packets_cache[file_id]
        
        # Apply sorting
        reverse = (sort_order == 'desc')
        if sort_field == 'timestamp':
            sorted_packets = sorted(all_packets, key=lambda x: x['timestamp'], reverse=reverse)
        elif sort_field == 'protocol':
            sorted_packets = sorted(all_packets, key=lambda x: x['protocol'], reverse=reverse)
        elif sort_field == 'length':
            sorted_packets = sorted(all_packets, key=lambda x: x['length'], reverse=reverse)
        else:
            sorted_packets = all_packets
        
        # Paginate
        total_packets = len(sorted_packets)
        total_pages = (total_packets + per_page - 1) // per_page
        start_idx = (page - 1) * per_page
        end_idx = min(start_idx + per_page, total_packets)
        page_packets = sorted_packets[start_idx:end_idx]
        
        return jsonify({
            'packets': page_packets,
            'page': page,
            'per_page': per_page,
            'total_packets': total_packets,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1,
            'sort_field': sort_field,
            'sort_order': sort_order
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/files', methods=['GET'])
def list_files():
    """List all uploaded files."""
    files = []
    for f in UPLOAD_FOLDER.glob('*'):
        if f.is_file():
            parts = f.name.split('_', 1)
            file_id = parts[0]
            filename = parts[1] if len(parts) > 1 else f.name
            files.append({
                'file_id': file_id,
                'filename': filename,
                'size': f.stat().st_size,
                'analyzed': file_id in analysis_cache
            })
    return jsonify(files)


# ==========================================
# Live Capture API Endpoints
# ==========================================

@app.route('/api/live/interfaces', methods=['GET'])
def get_interfaces():
    """Get list of available network interfaces."""
    global live_capture
    if live_capture is None:
        live_capture = LiveCapture(socketio)
    return jsonify(live_capture.get_interfaces())


@app.route('/api/live/start', methods=['POST'])
def start_capture():
    """Start live packet capture."""
    global live_capture
    if live_capture is None:
        live_capture = LiveCapture(socketio)
    
    data = request.get_json() or {}
    interface = data.get('interface')
    bpf_filter = data.get('filter')
    
    result = live_capture.start_capture(interface, bpf_filter)
    return jsonify(result)


@app.route('/api/live/stop', methods=['POST'])
def stop_capture():
    """Stop live packet capture."""
    global live_capture
    if live_capture is None:
        return jsonify({'error': 'No capture running'}), 400
    
    result = live_capture.stop_capture()
    return jsonify(result)


@app.route('/api/live/pause', methods=['POST'])
def pause_capture():
    """Pause/resume live capture."""
    global live_capture
    if live_capture is None:
        return jsonify({'error': 'No capture running'}), 400
    
    result = live_capture.pause_capture()
    return jsonify(result)


@app.route('/api/live/stats', methods=['GET'])
def get_capture_stats():
    """Get current capture statistics."""
    global live_capture
    if live_capture is None:
        return jsonify({'status': 'idle'})
    
    return jsonify(live_capture.get_stats())


@app.route('/api/live/save', methods=['POST'])
def save_capture():
    """Save captured packets to PCAP file."""
    global live_capture
    if live_capture is None:
        return jsonify({'error': 'No capture data'}), 400
    
    data = request.get_json() or {}
    filename = data.get('filename', f'capture_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap')
    
    # Save to captures folder
    captures_folder = UPLOAD_FOLDER.parent / 'captures'
    captures_folder.mkdir(exist_ok=True)
    filepath = captures_folder / filename
    
    result = live_capture.save_to_pcap(str(filepath))
    
    if result.get('success'):
        return jsonify({
            'success': True,
            'filename': filename,
            'path': str(filepath),
            'packet_count': result.get('packet_count'),
            'size': result.get('bytes')
        })
    else:
        return jsonify(result), 400


# WebSocket events
@socketio.on('connect')
def handle_connect():
    print('[+] Client connected to WebSocket')
    emit('connected', {'status': 'connected'})


@socketio.on('disconnect')
def handle_disconnect():
    print('[-] Client disconnected from WebSocket')


if __name__ == '__main__':
    # Check for admin privileges on Windows
    if os.name == 'nt':
        import ctypes
        import sys
        
        def is_admin():
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False

        if not is_admin():
            print("\n" + "!"*60)
            print("  WARNING: Administrative privileges are required for simple packet capture.")
            print("  Requesting elevation...")
            print("!"*60 + "\n")
            
            # Re-run the program with admin rights
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sys.exit() # Exit this non-admin instance
            except Exception as e:
                print(f"Failed to elevate privileges: {e}")
                print("Please run this script as Administrator manually.")
    
    print("\n" + "="*60)
    print("  Network Packet Investigator - Web Dashboard")
    print("  With Live Packet Capture Support")
    print("="*60)
    print(f"\n  Dashboard: http://localhost:5000")
    print(f"  API Docs:  http://localhost:5000/api/")
    print("\n  Press Ctrl+C to stop the server")
    print("="*60 + "\n")
    
    # Use socketio.run for WebSocket support
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
