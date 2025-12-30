/**
 * Network Packet Investigator - Dashboard Application
 * Main JavaScript Controller
 */

// API Base URL
const API_BASE = '';

// Application State
const state = {
    currentFileId: null,
    analysisData: null,
    currentView: 'dashboard',
    charts: {}
};

// DOM Elements
const elements = {
    uploadZone: document.getElementById('uploadZone'),
    fileInput: document.getElementById('fileInput'),
    browseBtn: document.getElementById('browseBtn'),
    uploadSection: document.getElementById('uploadSection'),
    progressContainer: document.getElementById('progressContainer'),
    progressTitle: document.getElementById('progressTitle'),
    progressMessage: document.getElementById('progressMessage'),
    progressFill: document.getElementById('progressFill'),
    progressPercent: document.getElementById('progressPercent'),
    dashboardView: document.getElementById('dashboardView'),
    findingsView: document.getElementById('findingsView'),
    sessionsView: document.getElementById('sessionsView'),
    packetsView: document.getElementById('packetsView'),
    exportBtn: document.getElementById('exportBtn'),
    exportModal: document.getElementById('exportModal'),
    findingModal: document.getElementById('findingModal'),
    navBtns: document.querySelectorAll('.nav-btn')
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    initUploadHandlers();
    initNavigation();
    initFilters();
    initExport();
    initPacketTabs();
    initPagination();
});

// ==========================================
// Upload Handlers
// ==========================================

function initUploadHandlers() {
    // Click to browse
    elements.browseBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        elements.fileInput.click();
    });

    elements.uploadZone.addEventListener('click', () => {
        elements.fileInput.click();
    });

    // File selected
    elements.fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });

    // Drag and drop
    elements.uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        elements.uploadZone.classList.add('dragover');
    });

    elements.uploadZone.addEventListener('dragleave', () => {
        elements.uploadZone.classList.remove('dragover');
    });

    elements.uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        elements.uploadZone.classList.remove('dragover');

        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });
}

async function handleFileUpload(file) {
    // Validate file type (be lenient - server will do final validation)
    const validExtensions = ['.pcap', '.pcapng', '.cap', '.dmp', '.etl', '.snoop', '.pkt'];
    const extension = '.' + file.name.split('.').pop().toLowerCase();

    // Only warn if extension doesn't match, but still try to upload
    if (!validExtensions.includes(extension)) {
        console.warn('File extension not recognized, attempting upload anyway:', extension);
    }

    // Show progress
    showProgress('Uploading...', `Uploading ${file.name}`);
    updateProgress(10);

    try {
        // Upload file
        const formData = new FormData();
        formData.append('file', file);

        const uploadResponse = await fetch(`${API_BASE}/api/upload`, {
            method: 'POST',
            body: formData
        });

        if (!uploadResponse.ok) {
            const error = await uploadResponse.json();
            throw new Error(error.error || 'Upload failed');
        }

        const uploadResult = await uploadResponse.json();
        state.currentFileId = uploadResult.file_id;

        updateProgress(30);
        showProgress('Analyzing...', 'Parsing PCAP file and extracting data');

        // Run analysis
        const analysisResponse = await fetch(`${API_BASE}/api/analyze/${state.currentFileId}`);

        updateProgress(70);

        if (!analysisResponse.ok) {
            const error = await analysisResponse.json();
            throw new Error(error.error || 'Analysis failed');
        }

        state.analysisData = await analysisResponse.json();

        updateProgress(90);
        showProgress('Rendering...', 'Building visualizations');

        // Short delay for UX
        await new Promise(resolve => setTimeout(resolve, 500));

        updateProgress(100);

        // Show dashboard
        showDashboard();

    } catch (error) {
        console.error('Error:', error);
        showNotification(error.message, 'error');
        hideProgress();
    }
}

function showProgress(title, message) {
    elements.uploadSection.querySelector('.upload-zone').classList.add('hidden');
    elements.progressContainer.classList.remove('hidden');
    elements.progressTitle.textContent = title;
    elements.progressMessage.textContent = message;
}

function updateProgress(percent) {
    elements.progressFill.style.width = `${percent}%`;
    elements.progressPercent.textContent = `${percent}%`;
}

function hideProgress() {
    elements.progressContainer.classList.add('hidden');
    elements.uploadSection.querySelector('.upload-zone').classList.remove('hidden');
}

// ==========================================
// Dashboard Rendering
// ==========================================

function showDashboard() {
    // Hide upload section
    elements.uploadSection.classList.add('hidden');

    // Show dashboard
    elements.dashboardView.classList.remove('hidden');

    // Enable export
    elements.exportBtn.disabled = false;

    // Populate stats
    populateStats();

    // Create charts
    createCharts();

    // Populate findings preview
    populateRecentFindings();
}

function populateStats() {
    const data = state.analysisData;

    // Animate counter
    animateCounter('statPackets', data.stats.total_packets || 0);
    animateCounter('statTcp', data.stats.tcp_packets || 0);
    animateCounter('statDns', data.dns.queries?.length || 0);
    animateCounter('statHttp', data.http.requests?.length || 0);
    animateCounter('statThreats', data.summary.total || 0);

    // Threat breakdown
    document.getElementById('threatCritical').textContent = data.summary.critical || 0;
    document.getElementById('threatWarning').textContent = data.summary.warning || 0;
    document.getElementById('threatInfo').textContent = data.summary.info || 0;
}

function animateCounter(elementId, target) {
    const element = document.getElementById(elementId);
    const duration = 1000;
    const start = 0;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = Math.floor(start + (target - start) * easeOut);

        element.textContent = formatNumber(current);

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

function createCharts() {
    const data = state.analysisData;

    // Protocol Distribution Chart
    createProtocolChart(data.stats);

    // DNS Chart
    createDnsChart(data.dns);

    // Ports Chart
    createPortsChart(data.tcp);
}

function createProtocolChart(stats) {
    const ctx = document.getElementById('protocolChart').getContext('2d');

    if (state.charts.protocol) {
        state.charts.protocol.destroy();
    }

    state.charts.protocol = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP'],
            datasets: [{
                data: [
                    stats.tcp_packets || 0,
                    stats.udp_packets || 0,
                    stats.icmp_packets || 0,
                    stats.dns_packets || 0,
                    stats.http_packets || 0
                ],
                backgroundColor: [
                    '#6366f1',
                    '#22d3ee',
                    '#8b5cf6',
                    '#10b981',
                    '#f59e0b'
                ],
                borderWidth: 0,
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#94a3b8',
                        padding: 15,
                        usePointStyle: true,
                        font: {
                            family: 'Inter'
                        }
                    }
                }
            }
        }
    });
}

function createDnsChart(dnsData) {
    const ctx = document.getElementById('dnsChart').getContext('2d');

    if (state.charts.dns) {
        state.charts.dns.destroy();
    }

    const topDomains = dnsData.top_domains || [];
    const labels = topDomains.map(d => {
        const domain = d[0].replace(/\.$/, '');
        return domain.length > 25 ? domain.substring(0, 22) + '...' : domain;
    });
    const values = topDomains.map(d => d[1]);

    state.charts.dns = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Queries',
                data: values,
                backgroundColor: 'rgba(99, 102, 241, 0.7)',
                borderColor: '#6366f1',
                borderWidth: 1,
                borderRadius: 4,
                barThickness: 20
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                },
                y: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#94a3b8',
                        font: {
                            family: 'JetBrains Mono',
                            size: 10
                        }
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

function createPortsChart(tcpData) {
    const ctx = document.getElementById('portsChart').getContext('2d');

    if (state.charts.ports) {
        state.charts.ports.destroy();
    }

    const ports = tcpData.ports || {};
    const sortedPorts = Object.entries(ports)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    const labels = sortedPorts.map(p => `Port ${p[0]}`);
    const values = sortedPorts.map(p => p[1]);

    // Color based on common suspicious ports
    const colors = sortedPorts.map(p => {
        const port = parseInt(p[0]);
        if ([4444, 5555, 6666, 6667, 31337, 12345].includes(port)) {
            return '#ef4444'; // Critical
        } else if ([8080, 8443, 4443, 8888].includes(port)) {
            return '#f59e0b'; // Warning
        }
        return '#22d3ee'; // Normal
    });

    state.charts.ports = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Connections',
                data: values,
                backgroundColor: colors.map(c => c + 'aa'),
                borderColor: colors,
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: {
                        display: false
                    },
                    ticks: {
                        color: '#94a3b8',
                        font: {
                            family: 'JetBrains Mono',
                            size: 9
                        }
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: '#94a3b8'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

function populateRecentFindings() {
    const container = document.getElementById('recentFindings');
    const findings = state.analysisData.findings || [];

    if (findings.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="#10b981" stroke-width="2">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <p>No threats detected - Network traffic appears clean</p>
            </div>
        `;
        return;
    }

    // Show first 5 findings
    const recentFindings = findings.slice(0, 5);

    container.innerHTML = recentFindings.map(finding => `
        <div class="finding-item" data-finding-id="${finding.id}">
            <div class="finding-severity ${finding.severity.toLowerCase()}"></div>
            <div class="finding-content">
                <div class="finding-category">${finding.category}</div>
                <div class="finding-description">${finding.description}</div>
            </div>
        </div>
    `).join('');

    // Add click handlers
    container.querySelectorAll('.finding-item').forEach(item => {
        item.addEventListener('click', () => {
            const findingId = item.dataset.findingId;
            const finding = findings.find(f => f.id === findingId);
            if (finding) {
                showFindingDetail(finding);
            }
        });
    });
}

// ==========================================
// Navigation
// ==========================================

function initNavigation() {
    elements.navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const view = btn.dataset.view;
            switchView(view);

            // Update active state
            elements.navBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
        });
    });

    // View all findings button
    document.getElementById('viewAllFindings').addEventListener('click', () => {
        switchView('findings');
        elements.navBtns.forEach(b => {
            b.classList.toggle('active', b.dataset.view === 'findings');
        });
    });
}

function switchView(view) {
    state.currentView = view;

    // Hide all views
    elements.dashboardView.classList.add('hidden');
    elements.findingsView.classList.add('hidden');
    elements.sessionsView.classList.add('hidden');
    elements.packetsView.classList.add('hidden');

    // Show selected view
    switch (view) {
        case 'dashboard':
            elements.dashboardView.classList.remove('hidden');
            break;
        case 'findings':
            elements.findingsView.classList.remove('hidden');
            populateFindingsTable();
            break;
        case 'sessions':
            elements.sessionsView.classList.remove('hidden');
            populateSessionsGrid();
            break;
        case 'packets':
            elements.packetsView.classList.remove('hidden');
            populatePacketsView();
            break;
    }
}

// ==========================================
// Findings View
// ==========================================

function initFilters() {
    const severityFilter = document.getElementById('severityFilter');
    const searchFilter = document.getElementById('searchFilter');

    severityFilter.addEventListener('change', () => {
        populateFindingsTable();
    });

    searchFilter.addEventListener('input', debounce(() => {
        populateFindingsTable();
    }, 300));
}

function populateFindingsTable() {
    if (!state.analysisData) return;

    const tbody = document.getElementById('findingsTableBody');
    const severityFilter = document.getElementById('severityFilter').value;
    const searchFilter = document.getElementById('searchFilter').value.toLowerCase();

    let findings = state.analysisData.findings || [];

    // Apply filters
    if (severityFilter !== 'all') {
        findings = findings.filter(f => f.severity === severityFilter);
    }

    if (searchFilter) {
        findings = findings.filter(f =>
            f.category.toLowerCase().includes(searchFilter) ||
            f.description.toLowerCase().includes(searchFilter)
        );
    }

    if (findings.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" style="text-align: center; padding: 3rem; color: var(--text-muted);">
                    No findings match your filters
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = findings.map(finding => `
        <tr data-finding-id="${finding.id}">
            <td>
                <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
            </td>
            <td>${finding.category}</td>
            <td>${finding.description}</td>
            <td>
                <button class="btn btn-ghost" onclick="showFindingDetail(${JSON.stringify(finding).replace(/"/g, '&quot;')})">
                    View →
                </button>
            </td>
        </tr>
    `).join('');
}

function showFindingDetail(finding) {
    const modal = document.getElementById('findingModal');
    const title = document.getElementById('findingModalTitle');
    const body = document.getElementById('findingModalBody');

    title.textContent = finding.category;

    const details = finding.details || {};
    const detailsHtml = Object.entries(details).map(([key, value]) => `
        <div class="detail-item">
            <div class="detail-label">${key}</div>
            <div class="detail-value">${value}</div>
        </div>
    `).join('');

    body.innerHTML = `
        <div style="margin-bottom: 1rem;">
            <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
        </div>
        <p style="margin-bottom: 1.5rem; color: var(--text-secondary);">${finding.description}</p>
        <div class="detail-grid">
            ${detailsHtml}
        </div>
    `;

    modal.classList.remove('hidden');

    // Close handlers
    const closeBtn = document.getElementById('closeFindingModal');
    const backdrop = modal.querySelector('.modal-backdrop');

    const closeModal = () => modal.classList.add('hidden');

    closeBtn.onclick = closeModal;
    backdrop.onclick = closeModal;
}

// ==========================================
// Sessions View
// ==========================================

function populateSessionsGrid() {
    if (!state.analysisData) return;

    const container = document.getElementById('sessionsGrid');
    const sessions = state.analysisData.tcp.top_sessions || [];

    document.getElementById('sessionCount').textContent =
        `${state.analysisData.tcp.session_count || 0} total sessions`;

    if (sessions.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="grid-column: 1 / -1;">
                <p>No TCP sessions found</p>
            </div>
        `;
        return;
    }

    container.innerHTML = sessions.map(session => {
        const key = session.session_key;
        return `
            <div class="session-card">
                <div class="session-header">
                    <div class="session-endpoints">
                        <span class="session-ip">${key[0]}:${key[1]}</span>
                        <span class="session-arrow">⟷</span>
                        <span class="session-ip">${key[2]}:${key[3]}</span>
                    </div>
                </div>
                <div class="session-stats">
                    <div class="session-stat">
                        <div class="session-stat-value">${session.packet_count}</div>
                        <div class="session-stat-label">Packets</div>
                    </div>
                    <div class="session-stat">
                        <div class="session-stat-value">${formatBytes(session.src_to_dst_bytes)}</div>
                        <div class="session-stat-label">Sent</div>
                    </div>
                    <div class="session-stat">
                        <div class="session-stat-value">${formatBytes(session.dst_to_src_bytes)}</div>
                        <div class="session-stat-label">Received</div>
                    </div>
                    <div class="session-stat">
                        <div class="session-stat-value">${session.duration?.toFixed(1) || 0}s</div>
                        <div class="session-stat-label">Duration</div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ==========================================
// Export Functionality
// ==========================================

function initExport() {
    elements.exportBtn.addEventListener('click', () => {
        elements.exportModal.classList.remove('hidden');
    });

    document.getElementById('closeExportModal').addEventListener('click', () => {
        elements.exportModal.classList.add('hidden');
    });

    elements.exportModal.querySelector('.modal-backdrop').addEventListener('click', () => {
        elements.exportModal.classList.add('hidden');
    });

    document.getElementById('exportJson').addEventListener('click', () => {
        exportReport('json');
    });

    document.getElementById('exportCsv').addEventListener('click', () => {
        exportReport('csv');
    });
}

async function exportReport(format) {
    if (!state.currentFileId) return;

    try {
        const response = await fetch(`${API_BASE}/api/export/${state.currentFileId}/${format}`);

        if (!response.ok) {
            throw new Error('Export failed');
        }

        if (format === 'json') {
            const data = await response.json();
            downloadFile(
                JSON.stringify(data, null, 2),
                `npi_report_${state.currentFileId}.json`,
                'application/json'
            );
        } else {
            const text = await response.text();
            downloadFile(
                text,
                `npi_report_${state.currentFileId}.csv`,
                'text/csv'
            );
        }

        elements.exportModal.classList.add('hidden');
        showNotification('Report exported successfully!', 'success');

    } catch (error) {
        showNotification(error.message, 'error');
    }
}

function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ==========================================
// Utilities
// ==========================================

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'error' ? 'var(--critical-bg)' : 'var(--success-bg)'};
        color: ${type === 'error' ? 'var(--critical)' : 'var(--success)'};
        border: 1px solid ${type === 'error' ? 'var(--critical)' : 'var(--success)'};
        border-radius: var(--radius-lg);
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease forwards';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Make showFindingDetail globally available
window.showFindingDetail = showFindingDetail;

// Add notification animations to document
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// ==========================================
// Packets View
// ==========================================

// Packet sorting state
let packetSortField = 'timestamp';
let packetSortOrder = 'asc';

function initPacketTabs() {
    const tabs = document.querySelectorAll('.packet-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const packetType = tab.dataset.packetType;

            // Update active tab
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Show corresponding panel
            document.querySelectorAll('.packet-panel').forEach(panel => {
                panel.classList.add('hidden');
            });
            document.getElementById(`${packetType}PacketsPanel`).classList.remove('hidden');
        });
    });

    // Sort controls - local sorting only (affects current page)
    const sortFieldSelect = document.getElementById('packetSortField');
    const sortOrderSelect = document.getElementById('packetSortOrder');

    if (sortFieldSelect) {
        sortFieldSelect.addEventListener('change', (e) => {
            packetSortField = e.target.value;
            // Sort current page locally - instant, stays on same page!
            sortCurrentPagePackets();
            // Re-sort other tabs too
            populateUdpPackets();
            populateDnsPackets();
            populateHttpPackets();
            populateTcpPackets();
        });
    }

    if (sortOrderSelect) {
        sortOrderSelect.addEventListener('change', (e) => {
            packetSortOrder = e.target.value;
            // Sort current page locally - instant, stays on same page!
            sortCurrentPagePackets();
            // Re-sort other tabs too
            populateUdpPackets();
            populateDnsPackets();
            populateHttpPackets();
            populateTcpPackets();
        });
    }
}

function sortPackets(packets) {
    if (!packets || packets.length === 0) return packets;

    return [...packets].sort((a, b) => {
        let aVal, bVal;

        switch (packetSortField) {
            case 'timestamp':
                aVal = a.timestamp || 0;
                bVal = b.timestamp || 0;
                break;
            case 'protocol':
                aVal = (a.protocol || '').toLowerCase();
                bVal = (b.protocol || '').toLowerCase();
                break;
            case 'length':
                aVal = a.length || a.payload_size || 0;
                bVal = b.length || b.payload_size || 0;
                break;
            default:
                aVal = a.timestamp || 0;
                bVal = b.timestamp || 0;
        }

        if (packetSortField === 'protocol') {
            // String comparison
            if (packetSortOrder === 'asc') {
                return aVal.localeCompare(bVal);
            } else {
                return bVal.localeCompare(aVal);
            }
        } else {
            // Numeric comparison
            if (packetSortOrder === 'asc') {
                return aVal - bVal;
            } else {
                return bVal - aVal;
            }
        }
    });
}

function populatePacketsView() {
    if (!state.analysisData) return;

    populateAllPackets();
    populateUdpPackets();
    populateDnsPackets();
    populateHttpPackets();
    populateTcpPackets();
}

// Pagination state
let allPacketsPage = 1;
let allPacketsTotalPages = 1;
let allPacketsTotalCount = 0;
let currentPagePackets = []; // Store current page's packets for local sorting
const PACKETS_PER_PAGE = 50;

// Sort current page packets locally (doesn't re-fetch)
function sortCurrentPagePackets() {
    if (!currentPagePackets || currentPagePackets.length === 0) return;

    const sortField = document.getElementById('packetSortField')?.value || 'timestamp';
    const sortOrder = document.getElementById('packetSortOrder')?.value || 'asc';
    const reverse = sortOrder === 'desc';

    const sorted = [...currentPagePackets].sort((a, b) => {
        let aVal, bVal;

        if (sortField === 'timestamp') {
            aVal = a.timestamp || 0;
            bVal = b.timestamp || 0;
        } else if (sortField === 'protocol') {
            aVal = (a.protocol || '').toLowerCase();
            bVal = (b.protocol || '').toLowerCase();
            return reverse ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
        } else if (sortField === 'length') {
            aVal = a.length || 0;
            bVal = b.length || 0;
        } else {
            aVal = a.timestamp || 0;
            bVal = b.timestamp || 0;
        }

        return reverse ? bVal - aVal : aVal - bVal;
    });

    // Re-render with sorted packets
    renderPacketsList(sorted);
}

function renderPacketsList(packets) {
    const container = document.getElementById('allPacketsList');

    container.innerHTML = packets.map((pkt) => `
        <div class="packet-card">
            <div class="packet-card-header">
                <div class="packet-card-title">
                    <span class="packet-type-badge ${pkt.protocol?.toLowerCase()}">${pkt.protocol || 'IP'}</span>
                    <span class="packet-endpoint">${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''} → ${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}</span>
                </div>
                <span class="packet-timestamp">#${pkt.index} • ${formatTimestamp(pkt.timestamp)}</span>
            </div>
            <div class="packet-card-body">
                <div class="packet-info-grid">
                    <div class="packet-info-item">
                        <div class="packet-info-label">Protocol</div>
                        <div class="packet-info-value">${pkt.protocol || 'Unknown'}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Length</div>
                        <div class="packet-info-value">${pkt.length || 0} bytes</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Source</div>
                        <div class="packet-info-value">${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Destination</div>
                        <div class="packet-info-value">${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}</div>
                    </div>
                </div>
                ${pkt.payload ? `
                    <div class="packet-content-label">Payload (${pkt.payload_size || 0} bytes)</div>
                    <div class="packet-content">${escapeHtml(pkt.payload)}</div>
                ` : ''}
            </div>
        </div>
    `).join('');
}

async function populateAllPackets(page = 1) {
    const container = document.getElementById('allPacketsList');

    if (!state.currentFileId) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No file loaded</p>
            </div>
        `;
        return;
    }

    // Show loading state
    container.innerHTML = `
        <div class="empty-state">
            <p>Loading packets... Page ${page}</p>
        </div>
    `;

    try {
        // Get sort options
        const sortField = document.getElementById('packetSortField')?.value || 'timestamp';
        const sortOrder = document.getElementById('packetSortOrder')?.value || 'asc';

        // Fetch packets from server (no sorting in URL - we sort locally)
        const response = await fetch(`${API_BASE}/api/packets/${state.currentFileId}?page=${page}&per_page=${PACKETS_PER_PAGE}`);
        const data = await response.json();

        if (data.error) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>Error: ${data.error}</p>
                </div>
            `;
            return;
        }

        const packets = data.packets || [];
        allPacketsPage = data.page;
        allPacketsTotalPages = data.total_pages;
        allPacketsTotalCount = data.total_packets;

        // Store for local sorting
        currentPagePackets = packets;

        if (packets.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>No packets found in this capture</p>
                </div>
            `;
            updatePaginationControls(0, 0, 0);
            return;
        }

        // Render with current sort settings
        sortCurrentPagePackets();

        // Update pagination controls
        updatePaginationControls(allPacketsPage, allPacketsTotalPages, allPacketsTotalCount);

    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                <p>Failed to load packets: ${error.message}</p>
            </div>
        `;
    }
}

function updatePaginationControls(currentPage, totalPages, totalPackets) {
    const pageInfo = document.getElementById('allPacketsPageInfo');
    const totalInfo = document.getElementById('allPacketsTotal');
    const firstBtn = document.getElementById('allPacketsFirst');
    const prevBtn = document.getElementById('allPacketsPrev');
    const nextBtn = document.getElementById('allPacketsNext');
    const lastBtn = document.getElementById('allPacketsLast');

    if (pageInfo) pageInfo.textContent = `Page ${currentPage} of ${totalPages || 1}`;
    if (totalInfo) totalInfo.textContent = `${totalPackets.toLocaleString()} total packets`;

    if (firstBtn) firstBtn.disabled = currentPage <= 1;
    if (prevBtn) prevBtn.disabled = currentPage <= 1;
    if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
    if (lastBtn) lastBtn.disabled = currentPage >= totalPages;
}

function initPagination() {
    document.getElementById('allPacketsFirst')?.addEventListener('click', () => populateAllPackets(1));
    document.getElementById('allPacketsPrev')?.addEventListener('click', () => populateAllPackets(allPacketsPage - 1));
    document.getElementById('allPacketsNext')?.addEventListener('click', () => populateAllPackets(allPacketsPage + 1));
    document.getElementById('allPacketsLast')?.addEventListener('click', () => populateAllPackets(allPacketsTotalPages));
}

function populateUdpPackets() {
    const container = document.getElementById('udpPacketsList');
    let packets = state.analysisData.udp?.packets || [];

    // Apply sorting
    packets = sortPackets(packets);

    if (packets.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No UDP/TFTP packets found in this capture</p>
            </div>
        `;
        return;
    }

    container.innerHTML = packets.map((pkt, index) => `
        <div class="packet-card">
            <div class="packet-card-header">
                <div class="packet-card-title">
                    <span class="packet-type-badge ${pkt.protocol?.toLowerCase()}">${pkt.protocol || 'UDP'}</span>
                    <span class="packet-endpoint">${pkt.src_ip}:${pkt.src_port} → ${pkt.dst_ip}:${pkt.dst_port}</span>
                </div>
                <span class="packet-timestamp">${formatTimestamp(pkt.timestamp)}</span>
            </div>
            <div class="packet-card-body">
                <div class="packet-info-grid">
                    <div class="packet-info-item">
                        <div class="packet-info-label">Protocol</div>
                        <div class="packet-info-value">${pkt.protocol || 'UDP'}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Length</div>
                        <div class="packet-info-value">${pkt.length || 0} bytes</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Source</div>
                        <div class="packet-info-value">${pkt.src_ip}:${pkt.src_port}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Destination</div>
                        <div class="packet-info-value">${pkt.dst_ip}:${pkt.dst_port}</div>
                    </div>
                </div>
                ${pkt.payload ? `
                    <div class="packet-content-label">Payload (${pkt.payload_size || 0} bytes)</div>
                    <div class="packet-content">${escapeHtml(pkt.payload)}</div>
                ` : ''}
            </div>
        </div>
    `).join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function populateDnsPackets() {
    const container = document.getElementById('dnsPacketsList');
    let queries = state.analysisData.dns.queries || [];

    // Apply sorting
    queries = sortPackets(queries);

    if (queries.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No DNS queries found in this capture</p>
            </div>
        `;
        return;
    }

    container.innerHTML = queries.slice(0, 50).map((query, index) => `
        <div class="packet-card">
            <div class="packet-card-header">
                <div class="packet-card-title">
                    <span class="packet-type-badge dns">DNS</span>
                    <span class="packet-endpoint">${query.src_ip || 'Unknown'} → ${query.dst_ip || 'Unknown'}</span>
                </div>
                <span class="packet-timestamp">${formatTimestamp(query.timestamp)}</span>
            </div>
            <div class="packet-card-body">
                <div class="packet-info-grid">
                    <div class="packet-info-item">
                        <div class="packet-info-label">Query Name</div>
                        <div class="packet-info-value dns-query-name">${query.query || 'N/A'}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Query Type</div>
                        <div class="packet-info-value">
                            <span class="dns-query-type">${query.qtype_name || 'A'}</span>
                        </div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Source IP</div>
                        <div class="packet-info-value">${query.src_ip || 'N/A'}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Destination IP</div>
                        <div class="packet-info-value">${query.dst_ip || 'N/A'}</div>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

function populateHttpPackets() {
    const container = document.getElementById('httpPacketsList');
    let requests = state.analysisData.http.requests || [];

    // Apply sorting
    requests = sortPackets(requests);

    if (requests.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No HTTP requests found in this capture</p>
            </div>
        `;
        return;
    }

    container.innerHTML = requests.slice(0, 50).map((req, index) => `
        <div class="packet-card">
            <div class="packet-card-header">
                <div class="packet-card-title">
                    <span class="packet-type-badge http">HTTP</span>
                    <span class="http-method ${req.method?.toLowerCase()}">${req.method || 'GET'}</span>
                    <span class="http-path">${req.path || '/'}</span>
                </div>
                <span class="packet-timestamp">${formatTimestamp(req.timestamp)}</span>
            </div>
            <div class="packet-card-body">
                <div class="packet-info-grid">
                    <div class="packet-info-item">
                        <div class="packet-info-label">Host</div>
                        <div class="packet-info-value">${req.host || 'N/A'}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Path</div>
                        <div class="packet-info-value">${req.path || '/'}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Source</div>
                        <div class="packet-info-value">${req.src_ip || 'N/A'}:${req.src_port || 'N/A'}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Destination</div>
                        <div class="packet-info-value">${req.dst_ip || 'N/A'}:${req.dst_port || 'N/A'}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">User-Agent</div>
                        <div class="packet-info-value">${req.user_agent || 'N/A'}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Content Length</div>
                        <div class="packet-info-value">${req.content_length || 0} bytes</div>
                    </div>
                </div>
                ${req.headers ? `
                    <div class="packet-content-label">Headers</div>
                    <div class="packet-content">${formatHeaders(req.headers)}</div>
                ` : ''}
            </div>
        </div>
    `).join('');
}

function populateTcpPackets() {
    const container = document.getElementById('tcpPacketsList');
    let connections = state.analysisData.tcp.connections || [];

    // Apply sorting
    connections = sortPackets(connections);

    if (connections.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No TCP connection attempts found in this capture</p>
            </div>
        `;
        return;
    }

    container.innerHTML = connections.slice(0, 50).map((conn, index) => `
        <div class="packet-card">
            <div class="packet-card-header">
                <div class="packet-card-title">
                    <span class="packet-type-badge tcp">TCP</span>
                    <span class="packet-endpoint">${conn.src_ip}:${conn.src_port} → ${conn.dst_ip}:${conn.dst_port}</span>
                </div>
                <span class="packet-timestamp">${formatTimestamp(conn.timestamp)}</span>
            </div>
            <div class="packet-card-body">
                <div class="packet-info-grid">
                    <div class="packet-info-item">
                        <div class="packet-info-label">Source IP</div>
                        <div class="packet-info-value">${conn.src_ip}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Source Port</div>
                        <div class="packet-info-value">${conn.src_port}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Destination IP</div>
                        <div class="packet-info-value">${conn.dst_ip}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">Destination Port</div>
                        <div class="packet-info-value">${conn.dst_port}</div>
                    </div>
                    <div class="packet-info-item">
                        <div class="packet-info-label">TCP Flags</div>
                        <div class="packet-info-value">${conn.flags || 'N/A'}</div>
                    </div>
                </div>
            </div>
        </div>
    `).join('');
}

function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    try {
        const date = new Date(timestamp * 1000);
        // Get hours, minutes, seconds
        const hours = date.getHours().toString().padStart(2, '0');
        const minutes = date.getMinutes().toString().padStart(2, '0');
        const seconds = date.getSeconds().toString().padStart(2, '0');
        // Get milliseconds from the fractional part of the timestamp
        const ms = Math.floor((timestamp % 1) * 1000).toString().padStart(3, '0');
        return `${hours}:${minutes}:${seconds}.${ms}`;
    } catch {
        return 'N/A';
    }
}

function formatHeaders(headers) {
    if (!headers || typeof headers !== 'object') return '';
    return Object.entries(headers)
        .map(([key, value]) => `${key}: ${value}`)
        .join('\n');
}

