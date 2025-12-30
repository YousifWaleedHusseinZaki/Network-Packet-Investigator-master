# Network Packet Investigator (NPI)

A powerful, modular CLI tool for analyzing network packet captures (PCAP files) and detecting suspicious activities such as phishing, data exfiltration, DNS tunneling, and more.

## Installation & Setup

### Prerequisites
1.  **Python 3.8+** installed.
2.  **Npcap** (Windows) or **libpcap** (Linux/macOS) installed.
    *   *Windows User:* Download Npcap from [npcap.com](https://npcap.com/). **Important:** Check "Install Npcap in WinPcap API-compatible Mode" during installation.

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
You can run the application in two modes:

#### 🌐 Web Dashboard (Recommended)
This launches the full GUI with PCAP analysis and Live Capture support.
```bash
# Windows (Run as Administrator for Live Capture)
python api_server.py
```
*   Access the dashboard at: **http://localhost:5000**

#### 🖥️ CLI Mode
Analyze files directly from the terminal.
```bash
python main.py -f path/to/capture.pcap
```

## 🔥 New Feature: Live Packet Capture
The Web Dashboard now includes a Wireshark-like **Live Capture** feature!
1.  Navigate to the **Live Capture** tab in the dashboard.
2.  Select your **Network Interface** (e.g., Wi-Fi, Ethernet).
3.  (Optional) Enter a BPF filter (e.g., `tcp port 80`).
4.  Click **Start Capture** to see packets in real-time.
5.  Use **Pause/Stop** to control the session.
6.  Click **Save PCAP** to export your capture to a file.

> **Note:** On Windows, you must run `python api_server.py` as **Administrator** to access network interfaces for live capture. The application will attempt to auto-elevate if needed.

## Features

### Protocol Parsers
- **PCAP Parser**: Load and analyze packet capture files
- **DNS Parser**: Extract DNS queries, responses, and analyze query patterns
- **HTTP Parser**: Extract HTTP requests/responses with full header analysis
- **TCP Parser**: Session tracking, connection analysis, and flow reconstruction

### Detection Capabilities
- **DNS Anomaly Detection**
  - DGA (Domain Generation Algorithm) detection via entropy analysis
  - DNS tunneling detection
  - Suspicious TLD identification
  - Excessive subdomain detection
  
- **HTTP Analysis**
  - Suspicious user-agent detection
  - Malicious path identification
  - Large upload detection
  - POST request analysis

- **Data Exfiltration Detection**
  - Large outbound transfer detection
  - DNS-based exfiltration
  - ICMP covert channels
  - HTTP-based data leakage

- **Phishing Detection**
  - Typosquatting identification
  - IDN homograph attack detection
  - Suspicious subdomain patterns
  - Credential submission monitoring

- **Traffic Analysis**
  - Malicious port detection
  - Port scanning identification
  - C2 communication patterns
  - Beaconing behavior detection
