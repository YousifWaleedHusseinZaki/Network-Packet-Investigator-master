/**
 * Live Packet Capture Module
 * Real-time packet capture with WebSocket streaming
 */

// Socket.IO connection
let socket = null;
let isCapturing = false;
let isPaused = false;
let capturedPackets = [];
const MAX_VISIBLE_PACKETS = 500;

// Initialize live capture
function initLiveCapture() {
    loadInterfaces();
    setupLiveCaptureEvents();
    setupLiveNavigation();
    connectWebSocket();
}

// Setup navigation for Live Capture view
function setupLiveNavigation() {
    const liveNavBtn = document.querySelector('[data-view="live"]');
    const allNavBtns = document.querySelectorAll('.nav-btn');

    if (liveNavBtn) {
        liveNavBtn.addEventListener('click', () => {
            // Update active nav button
            allNavBtns.forEach(btn => btn.classList.remove('active'));
            liveNavBtn.classList.add('active');

            // Hide all views
            document.querySelectorAll('.dashboard-section').forEach(section => {
                section.classList.add('hidden');
            });

            // Also hide upload section and results
            const uploadSection = document.getElementById('uploadSection');
            const resultsSection = document.getElementById('resultsSection');
            if (uploadSection) uploadSection.classList.add('hidden');
            if (resultsSection) resultsSection.classList.add('hidden');

            // Show live view
            const liveView = document.getElementById('liveView');
            if (liveView) {
                liveView.classList.remove('hidden');
            }
        });
    }
}

// Connect to WebSocket server
function connectWebSocket() {
    // Load Socket.IO library dynamically
    if (typeof io === 'undefined') {
        const script = document.createElement('script');
        script.src = 'https://cdn.socket.io/4.7.4/socket.io.min.js';
        script.onload = () => {
            socket = io();
            setupSocketEvents();
        };
        document.head.appendChild(script);
    } else {
        socket = io();
        setupSocketEvents();
    }
}

// Setup socket events
function setupSocketEvents() {
    if (!socket) return;

    socket.on('connect', () => {
        console.log('[+] WebSocket connected');
    });

    socket.on('disconnect', () => {
        console.log('[-] WebSocket disconnected');
        updateLiveIndicator(false);
    });

    socket.on('packet', (pkt) => {
        addLivePacket(pkt);
    });

    socket.on('capture_status', (status) => {
        handleCaptureStatus(status);
    });

    socket.on('capture_stats', (stats) => {
        updateLiveStats(stats);
    });

    socket.on('capture_error', (error) => {
        console.error('Capture error:', error);
        alert('Capture Error: ' + error.error);
        stopCaptureUI();
    });
}

// Load available network interfaces
async function loadInterfaces() {
    const select = document.getElementById('interfaceSelect');
    if (!select) return;

    try {
        const response = await fetch('/api/live/interfaces');
        const interfaces = await response.json();

        select.innerHTML = '<option value="">-- Select Interface --</option>';

        if (interfaces.length === 0) {
            select.innerHTML = '<option value="">⚠️ No interfaces - Run as Administrator</option>';
            return;
        }

        interfaces.forEach(iface => {
            const option = document.createElement('option');
            // Use ID (robust device path) for value, not friendly name
            option.value = iface.id || iface.name;
            // Show description with IP if available
            let label = iface.description || iface.name;
            if (iface.ip) {
                label += ` [${iface.ip}]`;
            } else if (iface.mac && iface.mac !== 'Unknown') {
                label += ` (${iface.mac})`;
            }
            option.textContent = label;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Failed to load interfaces:', error);
        select.innerHTML = '<option value="">⚠️ Error loading interfaces - Run as Administrator</option>';
    }
}

// Setup event listeners
function setupLiveCaptureEvents() {
    const startBtn = document.getElementById('startCaptureBtn');
    const pauseBtn = document.getElementById('pauseCaptureBtn');
    const stopBtn = document.getElementById('stopCaptureBtn');
    const saveBtn = document.getElementById('saveCaptureBtn');

    if (startBtn) {
        startBtn.addEventListener('click', startCapture);
    }
    if (pauseBtn) {
        pauseBtn.addEventListener('click', pauseCapture);
    }
    if (stopBtn) {
        stopBtn.addEventListener('click', stopCapture);
    }
    if (saveBtn) {
        saveBtn.addEventListener('click', saveCapture);
    }
}

// Start capture
async function startCapture() {
    const interfaceSelect = document.getElementById('interfaceSelect');
    const bpfFilter = document.getElementById('bpfFilter');

    const selectedInterface = interfaceSelect?.value;
    const filter = bpfFilter?.value || '';

    if (!selectedInterface) {
        alert('Please select a network interface');
        return;
    }

    try {
        const response = await fetch('/api/live/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                interface: selectedInterface,
                filter: filter
            })
        });

        const result = await response.json();

        if (result.error) {
            alert('Error starting capture: ' + result.error);
            return;
        }

        // Clear previous packets
        capturedPackets = [];
        const packetBody = document.getElementById('livePacketBody');
        if (packetBody) {
            packetBody.innerHTML = '';
        }

        isCapturing = true;
        isPaused = false;
        updateCaptureButtons();
        updateLiveIndicator(true);

    } catch (error) {
        console.error('Failed to start capture:', error);
        alert('Failed to start capture: ' + error.message);
    }
}

// Pause/resume capture
async function pauseCapture() {
    try {
        const response = await fetch('/api/live/pause', {
            method: 'POST'
        });

        const result = await response.json();
        isPaused = result.status === 'paused';

        const pauseBtn = document.getElementById('pauseCaptureBtn');
        if (pauseBtn) {
            pauseBtn.innerHTML = isPaused ? '<span>▶</span> Resume' : '<span>⏸</span> Pause';
        }

    } catch (error) {
        console.error('Failed to pause capture:', error);
    }
}

// Stop capture
async function stopCapture() {
    try {
        const response = await fetch('/api/live/stop', {
            method: 'POST'
        });

        const result = await response.json();
        stopCaptureUI();

    } catch (error) {
        console.error('Failed to stop capture:', error);
    }
}

function stopCaptureUI() {
    isCapturing = false;
    isPaused = false;
    updateCaptureButtons();
    updateLiveIndicator(false);
}

// Save capture to PCAP
async function saveCapture() {
    const filename = prompt('Enter filename:', `capture_${new Date().toISOString().slice(0, 19).replace(/[:-]/g, '')}.pcap`);

    if (!filename) return;

    try {
        const response = await fetch('/api/live/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename })
        });

        const result = await response.json();

        if (result.success) {
            alert(`Saved ${result.packet_count} packets to:\n${result.path}`);
        } else {
            alert('Failed to save: ' + result.error);
        }

    } catch (error) {
        console.error('Failed to save capture:', error);
        alert('Failed to save: ' + error.message);
    }
}

// Update button states
function updateCaptureButtons() {
    const startBtn = document.getElementById('startCaptureBtn');
    const pauseBtn = document.getElementById('pauseCaptureBtn');
    const stopBtn = document.getElementById('stopCaptureBtn');
    const saveBtn = document.getElementById('saveCaptureBtn');
    const interfaceSelect = document.getElementById('interfaceSelect');
    const bpfFilter = document.getElementById('bpfFilter');

    if (startBtn) startBtn.disabled = isCapturing;
    if (pauseBtn) pauseBtn.disabled = !isCapturing;
    if (stopBtn) stopBtn.disabled = !isCapturing;
    if (saveBtn) saveBtn.disabled = capturedPackets.length === 0;
    if (interfaceSelect) interfaceSelect.disabled = isCapturing;
    if (bpfFilter) bpfFilter.disabled = isCapturing;
}

// Update live indicator
function updateLiveIndicator(active) {
    const indicator = document.getElementById('liveIndicator');
    const label = indicator?.querySelector('.live-label');

    if (indicator) {
        if (active) {
            indicator.classList.add('active');
            if (label) label.textContent = 'LIVE';
        } else {
            indicator.classList.remove('active');
            if (label) label.textContent = 'OFFLINE';
        }
    }
}

// Add packet to live table
function addLivePacket(pkt) {
    capturedPackets.push(pkt);

    const packetBody = document.getElementById('livePacketBody');
    if (!packetBody) return;

    // Remove empty state if present
    const emptyState = packetBody.querySelector('.live-empty-state');
    if (emptyState) {
        emptyState.remove();
    }

    // Create packet row
    const row = document.createElement('div');
    row.className = `live-packet-row`;

    // Add threat level class
    if (pkt.threat_level && pkt.threat_level !== 'none') {
        row.classList.add(`threat-${pkt.threat_level}`);
    }

    // Format timestamp
    const timestamp = new Date(pkt.timestamp * 1000);
    const timeStr = timestamp.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3
    });

    // Protocol class for coloring
    const protoClass = `live-proto-${pkt.protocol.toLowerCase()}`;

    row.innerHTML = `
        <span class="col-no">${pkt.index}</span>
        <span class="col-time">${timeStr}</span>
        <span class="col-src">${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}</span>
        <span class="col-dst">${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}</span>
        <span class="col-proto ${protoClass}">${pkt.protocol}</span>
        <span class="col-len">${pkt.length}</span>
        <span class="col-info">${pkt.info || pkt.summary || ''}</span>
    `;

    packetBody.appendChild(row);

    // Auto-scroll to bottom
    packetBody.scrollTop = packetBody.scrollHeight;

    // Limit visible packets
    while (packetBody.children.length > MAX_VISIBLE_PACKETS) {
        packetBody.removeChild(packetBody.firstChild);
    }

    // Update save button
    const saveBtn = document.getElementById('saveCaptureBtn');
    if (saveBtn) saveBtn.disabled = false;
}

// Handle capture status updates
function handleCaptureStatus(status) {
    console.log('Capture status:', status);

    if (status.status === 'started') {
        isCapturing = true;
        updateLiveIndicator(true);
    } else if (status.status === 'stopped') {
        isCapturing = false;
        updateLiveIndicator(false);
    } else if (status.status === 'paused') {
        isPaused = true;
    } else if (status.status === 'resumed') {
        isPaused = false;
    }

    updateCaptureButtons();
}

// Update live stats
function updateLiveStats(stats) {
    const packetCount = document.getElementById('livePacketCount');
    const bytesCount = document.getElementById('liveBytesCount');
    const packetsPerSec = document.getElementById('livePacketsPerSec');
    const duration = document.getElementById('liveDuration');
    const protocolStats = document.getElementById('liveProtocolStats');

    if (packetCount) packetCount.textContent = stats.packet_count.toLocaleString();
    if (bytesCount) bytesCount.textContent = formatBytes(stats.bytes_captured);
    if (packetsPerSec) packetsPerSec.textContent = stats.packets_per_sec;
    if (duration) duration.textContent = formatDuration(stats.duration);

    // Update protocol stats
    if (protocolStats && stats.protocols) {
        protocolStats.innerHTML = Object.entries(stats.protocols)
            .map(([proto, count]) => `
                <div class="proto-stat">
                    <span class="proto-stat-name">${proto}:</span>
                    <span class="proto-stat-count">${count}</span>
                </div>
            `).join('');
    }
}

// Format bytes to human readable
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Format duration
function formatDuration(seconds) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    initLiveCapture();
});
