// Global state
let alertsData = [];
let chartSeverity = null;
let chartSources = null;
const API_BASE = ''; // Same origin

// SECURE RENDERING: HTML escaping helper to mitigate XSS vulnerabilities in dynamic rendering
function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag] || tag)
    );
}


// Initialize DOM Elements
document.addEventListener('DOMContentLoaded', () => {
    initApp();
    setupNavigation();
    setupEventListeners();
    startUTCClock();
});

// App Initialization
async function initApp() {
    await fetchStats();
    await fetchAlerts();
    await fetchWebhookSettings();
    applyPersistedSidebarState();
}

// Sidebar SPA Section Swapping
function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.dashboard-section');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();

            // Remove active from all items
            navItems.forEach(n => n.classList.remove('active'));
            // Add active to current
            item.classList.add('active');

            const targetId = item.getAttribute('href').replace('#', '');

            // Show target section, hide others
            sections.forEach(sec => {
                if (sec.id === targetId) {
                    sec.style.display = 'block';
                    // Scroll to top of content
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                } else {
                    sec.style.display = 'none';
                }
            });
        });
    });

    // Default: Show overview, hide others
    sections.forEach(sec => {
        if (sec.id === 'overview') {
            sec.style.display = 'block';
        } else {
            sec.style.display = 'none';
        }
    });
}

// Event Listeners setup
function setupEventListeners() {
    // Control Buttons
    document.getElementById('btn-trigger-scan').addEventListener('click', triggerOSINTScan);
    document.getElementById('btn-simulate-leak').addEventListener('click', injectMockLeak);
    document.getElementById('btn-clear-db').addEventListener('click', clearDatabase);

    // Simulator
    document.getElementById('btn-submit-simulation').addEventListener('click', submitSimulation);

    // Webhook settings listeners
    document.getElementById('btn-save-webhook').addEventListener('click', saveWebhookSettings);
    document.getElementById('btn-test-webhook').addEventListener('click', testWebhookSettings);
    document.getElementById('btn-toggle-webhook-visibility').addEventListener('click', toggleWebhookVisibility);

    // Table Action Exports
    document.getElementById('btn-export-csv').addEventListener('click', exportCSVReport);
    document.getElementById('btn-export-json').addEventListener('click', exportJSONReport);

    // OSINT Target Investigator
    document.getElementById('btn-submit-investigation').addEventListener('click', runOSINTInvestigation);

    // Sidebar Collapse
    document.getElementById('btn-toggle-sidebar').addEventListener('click', toggleSidebarState);

    // Filters
    document.getElementById('table-search').addEventListener('input', filterAlertsTable);
    document.getElementById('severity-filter').addEventListener('change', filterAlertsTable);

    // Modal Close
    document.querySelector('.close-modal').addEventListener('click', closeModal);
    window.addEventListener('click', (e) => {
        const modal = document.getElementById('detail-modal');
        if (e.target === modal) {
            closeModal();
        }
    });
}

// Fetch stats and update charts
async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats`);
        const stats = await response.json();

        // Update metric values in dashboard
        document.getElementById('stat-total-alerts').textContent = stats.total || 0;
        document.getElementById('stat-high-alerts').textContent = stats.severity.HIGH || 0;

        const medLowCount = (stats.severity.MEDIUM || 0) + (stats.severity.LOW || 0);
        document.getElementById('stat-med-low-alerts').textContent = medLowCount;

        // Update charts
        updateSeverityChart(stats.severity);
        updateSourcesChart(stats.source);
    } catch (error) {
        console.error("Error fetching stats:", error);
    }
}

// Fetch alerts list and populate table
async function fetchAlerts() {
    try {
        const response = await fetch(`${API_BASE}/api/alerts`);
        alertsData = await response.json();
        renderAlertsTable(alertsData);
    } catch (error) {
        console.error("Error fetching alerts:", error);
    }
}

// Render Table Rows
function renderAlertsTable(alerts) {
    const tableBody = document.getElementById('alerts-table-body');
    tableBody.innerHTML = '';

    if (alerts.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="px-4 py-8 text-center text-slate-500 font-medium">
                    <i class="fa-solid fa-folder-open text-2xl mb-2 block opacity-30"></i>
                    No alerts found. Trigger a scan or inject a leak.
                </td>
            </tr>
        `;
        return;
    }

    alerts.forEach(alert => {
        const tr = document.createElement('tr');
        tr.className = 'border-b border-slate-800 hover:bg-slate-800/30 transition-colors cursor-pointer';

        // Severity Badge (Muted colors with subtle border)
        let badgeClass = 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
        if (alert.severity === 'HIGH') badgeClass = 'bg-red-500/10 text-red-400 border border-red-500/20';
        if (alert.severity === 'MEDIUM') badgeClass = 'bg-amber-500/10 text-amber-400 border border-amber-500/20';

        tr.innerHTML = `
            <td class="px-4 py-3 font-mono font-bold text-slate-400">#${alert.id}</td>
            <td class="px-4 py-3 text-slate-400 whitespace-nowrap"><i class="fa-regular fa-clock mr-1 text-[10px] opacity-60"></i> ${alert.detected_at}</td>
            <td class="px-4 py-3 font-semibold text-slate-200">${escapeHTML(alert.source)}</td>
            <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${badgeClass}">${alert.severity}</span></td>
            <td class="px-4 py-3 font-medium text-slate-300 max-w-xs truncate" title="${escapeHTML(alert.matched_keyword)}">${escapeHTML(alert.matched_keyword)}</td>
            <td class="px-4 py-3 text-right">
                <button class="btn-view px-2.5 py-1 text-xs font-semibold rounded-md text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700/80 transition-colors cursor-pointer" data-id="${alert.id}">
                    <i class="fa-solid fa-eye text-[10px]"></i> View
                </button>
            </td>
        `;

        // Double-click row to inspect
        tr.addEventListener('dblclick', () => showDetailsModal(alert));

        // Button Click to inspect
        tr.querySelector('.btn-view').addEventListener('click', (e) => {
            e.stopPropagation();
            showDetailsModal(alert);
        });

        tableBody.appendChild(tr);
    });
}

// Filter alerts based on search and dropdown severity
function filterAlertsTable() {
    const query = document.getElementById('table-search').value.toLowerCase();
    const severity = document.getElementById('severity-filter').value;

    const filtered = alertsData.filter(alert => {
        const matchesQuery =
            alert.source.toLowerCase().includes(query) ||
            alert.matched_keyword.toLowerCase().includes(query) ||
            alert.leak_content.toLowerCase().includes(query);

        const matchesSeverity = (severity === 'ALL' || alert.severity === severity);

        return matchesQuery && matchesSeverity;
    });

    renderAlertsTable(filtered);
}

// Open Modal
function showDetailsModal(alert) {
    document.getElementById('modal-source').textContent = alert.source;
    document.getElementById('modal-time').textContent = alert.detected_at;
    document.getElementById('modal-keyword').textContent = alert.matched_keyword;

    const sevValue = document.getElementById('modal-severity');
    sevValue.textContent = alert.severity;
    
    // Set professional badge classes
    sevValue.className = 'text-xs font-bold px-2 py-0.5 rounded uppercase tracking-wider';
    if (alert.severity === 'HIGH') {
        sevValue.classList.add('bg-red-500/10', 'text-red-400', 'border', 'border-red-500/20');
    } else if (alert.severity === 'MEDIUM') {
        sevValue.classList.add('bg-amber-500/10', 'text-amber-400', 'border', 'border-amber-500/20');
    } else {
        sevValue.classList.add('bg-blue-500/10', 'text-blue-400', 'border', 'border-blue-500/20');
    }

    document.getElementById('modal-raw-content').textContent = alert.leak_content;

    const modal = document.getElementById('detail-modal');
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeModal() {
    const modal = document.getElementById('detail-modal');
    modal.classList.remove('flex');
    modal.classList.add('hidden');
}

// Trigger SSE Real-Time Scanning Logs
function triggerOSINTScan() {
    const btn = document.getElementById('btn-trigger-scan');
    const termOutput = document.getElementById('terminal-output');

    // Switch to Terminal Tab visually
    document.querySelector('a[href="#crawler"]').click();

    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Crawling...`;

    termOutput.innerHTML = '<div class="text-blue-400 font-medium">[~] Initializing active threat intelligence channels...</div>';

    const eventSource = new EventSource(`${API_BASE}/api/trigger-scan-logs`);

    eventSource.onmessage = (event) => {
        const line = document.createElement('div');
        
        // Color logs depending on tags using Tailwind
        if (event.data.includes('[!] ALERT')) {
            line.className = 'text-red-400 font-semibold';
        } else if (event.data.includes('[✔]')) {
            line.className = 'text-emerald-400 font-semibold';
        } else if (event.data.includes('[+]')) {
            line.className = 'text-blue-400';
        } else {
            line.className = 'text-slate-400';
        }

        line.textContent = event.data;
        termOutput.appendChild(line);
        termOutput.scrollTop = termOutput.scrollHeight;
    };

    eventSource.onerror = (err) => {
        eventSource.close();
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-magnifying-glass-chart"></i> Run Threat Scan`;

        // Refresh tables and stats
        initApp();
    };
}

// Inject Mock Leak
async function injectMockLeak() {
    const btn = document.getElementById('btn-simulate-leak');
    btn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/api/simulate-leak`, { method: 'POST' });
        const res = await response.json();

        if (res.status === 'success') {
            await initApp();

            // Pop terminal notification if visible
            const termOutput = document.getElementById('terminal-output');
            const line = document.createElement('div');
            line.className = 'text-amber-400 font-medium';
            line.textContent = `[!] LIVE ALERT DETECTED: Mock Leak Injected successfully into database (${res.alert.severity} risk - Source: ${res.alert.source})`;
            termOutput.appendChild(line);

            // Output webhook dispatches to terminal if they occurred
            if (res.webhook_logs && res.webhook_logs.length > 0) {
                res.webhook_logs.forEach(wl => {
                    const l = document.createElement('div');
                    l.className = 'text-blue-400 ml-4';
                    l.textContent = `    ${wl}`;
                    termOutput.appendChild(l);
                });
            }
            termOutput.scrollTop = termOutput.scrollHeight;

            // Flash dashboard stats
            const alertsMetric = document.getElementById('stat-total-alerts');
            alertsMetric.style.transform = 'scale(1.15)';
            alertsMetric.style.transition = 'transform 0.15s ease-out';
            setTimeout(() => alertsMetric.style.transform = 'scale(1)', 150);
        }
    } catch (err) {
        console.error("Error simulating leak:", err);
    } finally {
        btn.disabled = false;
    }
}

// Clear Database
async function clearDatabase() {
    if (!confirm("Are you sure you want to purge all records in the database? This is useful for demo resets.")) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/clear`, { method: 'POST' });
        const res = await response.json();

        if (res.status === 'success') {
            document.getElementById('terminal-output').innerHTML = '<div class="text-slate-400">[x] Threat intelligence database has been purged.</div>';
            await initApp();
        }
    } catch (err) {
        console.error("Error clearing DB:", err);
    }
}

// Submit Simulation scanner
async function submitSimulation() {
    const input = document.getElementById('simulation-input').value;
    const resultPane = document.getElementById('simulation-result');
    const btn = document.getElementById('btn-submit-simulation');

    if (!input.trim()) {
        alert("Please enter some text to scan.");
        return;
    }

    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Engine Analyzing...`;

    try {
        const response = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: input })
        });

        const res = await response.json();
        resultPane.innerHTML = '';
        resultPane.className = 'bg-slate-950 border border-slate-800 rounded-lg p-5 flex flex-col justify-between';

        if (res.status === 'threat_detected') {
            const alert = res.alert;
            resultPane.innerHTML = `
                <div class="space-y-4">
                    <div class="text-xs font-bold text-red-400 flex items-center gap-2">
                        <i class="fa-solid fa-triangle-exclamation"></i> CRITICAL VULNERABILITY DETECTED
                    </div>
                    <div class="space-y-2.5 text-xs text-slate-300">
                        <div class="flex justify-between border-b border-slate-800 pb-1.5">
                            <strong class="text-slate-500">Source Feed:</strong> <span>${escapeHTML(alert.source)}</span>
                        </div>
                        <div class="flex justify-between border-b border-slate-800 pb-1.5">
                            <strong class="text-slate-500">Assigned Severity:</strong>
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-500/10 text-red-400 border border-red-500/20">${alert.severity}</span>
                        </div>
                        <div class="flex flex-col gap-1">
                            <strong class="text-slate-500">Scan Indicator Match:</strong>
                            <div class="flex flex-wrap gap-1 mt-1">
                                <span class="bg-slate-800 text-slate-300 border border-slate-700 px-2 py-0.5 rounded font-medium">${escapeHTML(alert.matched_keyword)}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            // Output SOAR logs to terminal
            const termOutput = document.getElementById('terminal-output');
            const line = document.createElement('div');
            line.className = 'text-amber-400 font-medium';
            line.textContent = `[!] SIMULATION DETECTED THREAT: (${alert.severity} risk - Match: ${alert.matched_keyword})`;
            termOutput.appendChild(line);

            if (res.webhook_logs && res.webhook_logs.length > 0) {
                res.webhook_logs.forEach(wl => {
                    const l = document.createElement('div');
                    l.className = 'text-blue-400 ml-4';
                    l.textContent = `    ${wl}`;
                    termOutput.appendChild(l);
                });
            }
            termOutput.scrollTop = termOutput.scrollHeight;

            // Reload dashboard behind scenes
            await initApp();
        } else {
            resultPane.innerHTML = `
                <div class="result-threat">
                    <div class="result-header-clean">
                        <i class="fa-solid fa-circle-check"></i> SCAN STATUS: CLEAN
                    </div>
                    <div class="result-details">
                        <p style="font-size: 14px; color: var(--text-secondary); line-height: 1.5;">
                            Scanning was completed successfully. The text blocks were evaluated against active regex signatures (PII leaks, .go.id targets, system configuration flags). No indicators matched.
                        </p>
                    </div>
                </div>
            `;
            resultPane.style.borderColor = 'var(--neon-green)';
            resultPane.style.boxShadow = '0 0 15px rgba(57, 255, 20, 0.2)';
        }
    } catch (err) {
        console.error("Error running simulation:", err);
        resultPane.innerHTML = `<p style="color: var(--neon-red);">Error processing server scanning request.</p>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-microchip"></i> Analyze and Scan`;
    }
}

// Chart.js render: Severity distribution
function updateSeverityChart(severityData) {
    const ctx = document.getElementById('chart-severity').getContext('2d');

    const labels = ['High', 'Medium', 'Low'];
    const data = [
        severityData.HIGH || 0,
        severityData.MEDIUM || 0,
        severityData.LOW || 0
    ];

    if (chartSeverity) {
        chartSeverity.data.datasets[0].data = data;
        chartSeverity.update();
        return;
    }

    chartSeverity = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    '#ef4444',   // Incident red
                    '#f59e0b',   // Warning amber
                    '#3b82f6'    // Corporate info blue
                ],
                borderColor: '#1e293b',
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'Outfit', size: 12 }
                    }
                }
            }
        }
    });
}

// Chart.js render: Top incident sources
function updateSourcesChart(sourcesData) {
    const ctx = document.getElementById('chart-sources').getContext('2d');

    const labels = Object.keys(sourcesData);
    const data = Object.values(sourcesData);

    if (chartSources) {
        chartSources.data.labels = labels;
        chartSources.data.datasets[0].data = data;
        chartSources.update();
        return;
    }

    chartSources = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Alert Counts',
                data: data,
                backgroundColor: 'rgba(59, 130, 246, 0.7)',
                borderColor: '#3b82f6',
                borderWidth: 1,
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    ticks: { color: '#94a3b8', font: { family: 'Outfit', size: 10 } },
                    grid: { color: 'rgba(255,255,255,0.03)' }
                },
                y: {
                    ticks: { color: '#94a3b8', font: { family: 'Outfit', size: 11 }, precision: 0 },
                    grid: { color: 'rgba(255,255,255,0.03)' }
                }
            }
        }
    });
}

// --- NEW FUNCTIONS FOR WEBHOOKS, EXPORTS & INVESTIGATOR ---

// Webhook settings fetching
async function fetchWebhookSettings() {
    try {
        const response = await fetch(`${API_BASE}/api/webhook-settings`);
        const config = await response.json();

        document.getElementById('webhook-url').value = config.url || '';
        document.getElementById('webhook-severity').value = config.min_severity || 'HIGH';
    } catch (error) {
        console.error("Error fetching webhook settings:", error);
    }
}

// Save Webhook configuration
async function saveWebhookSettings() {
    const urlInput = document.getElementById('webhook-url').value.trim();
    const severitySelect = document.getElementById('webhook-severity').value;
    const statusLine = document.getElementById('webhook-status');

    statusLine.textContent = "Saving config...";
    statusLine.style.color = "var(--text-secondary)";

    try {
        const response = await fetch(`${API_BASE}/api/webhook-settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: urlInput,
                min_severity: severitySelect,
                enabled: urlInput.length > 0
            })
        });
        const res = await response.json();
        if (res.status === 'success') {
            statusLine.textContent = `[✔] Settings saved successfully. Integrations active: ${urlInput.length > 0 ? "ENABLED" : "DISABLED"}`;
            statusLine.style.color = "var(--neon-green)";
            setTimeout(() => { statusLine.textContent = ""; }, 4000);
        } else {
            statusLine.textContent = `[x] Error: ${res.message}`;
            statusLine.style.color = "var(--neon-red)";
        }
    } catch (error) {
        statusLine.textContent = `[x] Connection failed to save settings.`;
        statusLine.style.color = "var(--neon-red)";
    }
}

// Send Test Webhook
async function testWebhookSettings() {
    const urlInput = document.getElementById('webhook-url').value.trim();
    const severitySelect = document.getElementById('webhook-severity').value;
    const statusLine = document.getElementById('webhook-status');

    if (!urlInput) {
        statusLine.textContent = "[x] Error: Webhook URL cannot be empty for testing.";
        statusLine.style.color = "var(--neon-red)";
        return;
    }

    statusLine.textContent = "Sending webhook signal...";
    statusLine.style.color = "var(--neon-blue)";

    try {
        const response = await fetch(`${API_BASE}/api/webhook-settings`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: urlInput,
                min_severity: severitySelect,
                enabled: true,
                test: true
            })
        });
        const res = await response.json();
        if (res.test_success) {
            statusLine.textContent = `[✔] Test alert sent successfully! (${res.test_logs.join(' | ')})`;
            statusLine.style.color = "var(--neon-green)";
        } else {
            statusLine.textContent = `[x] Dispatch warning: ${res.test_logs.length > 0 ? res.test_logs[0] : "Check endpoint URL."}`;
            statusLine.style.color = "var(--neon-yellow)";
        }
    } catch (error) {
        statusLine.textContent = `[x] Error connecting to server dispatcher.`;
        statusLine.style.color = "var(--neon-red)";
    }
}

// Export CSV Report
function exportCSVReport() {
    if (alertsData.length === 0) {
        alert("No alerts data available to export.");
        return;
    }

    const headers = ['ID', 'Detected At', 'Source Feed', 'Severity', 'Vulnerabilities/Keywords', 'Raw Content'];
    const rows = alertsData.map(alert => [
        alert.id,
        alert.detected_at,
        `"${alert.source.replace(/"/g, '""')}"`,
        alert.severity,
        `"${alert.matched_keyword.replace(/"/g, '""')}"`,
        `"${alert.leak_content.replace(/\r?\n/g, ' ').replace(/"/g, '""')}"`
    ]);

    const csvContent = "\ufeff" + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `cerberus_threatintel_report_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Export JSON Report
function exportJSONReport() {
    if (alertsData.length === 0) {
        alert("No alerts data available to export.");
        return;
    }

    const jsonString = JSON.stringify(alertsData, null, 4);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `cerberus_threatintel_report_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// OSINT target investigation handler
async function runOSINTInvestigation() {
    const input = document.getElementById('investigator-input').value.trim();
    const btn = document.getElementById('btn-submit-investigation');
    const emptyContainer = document.getElementById('investigator-empty');
    const resultsContainer = document.getElementById('investigator-results-container');

    if (!input) {
        alert("Please enter an IP Address or Domain Target.");
        return;
    }

    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Tracing...`;

    try {
        const response = await fetch(`${API_BASE}/api/investigate?target=${encodeURIComponent(input)}`);
        const res = await response.json();

        if (response.status !== 200) {
            alert(res.message || "Failed to query investigation backend.");
            return;
        }

        // Hide placeholder, show results
        emptyContainer.style.display = 'none';
        resultsContainer.style.display = 'block';

        // 1. Threat Gauge Update
        const scoreCircle = document.getElementById('gauge-circle-element');
        scoreCircle.textContent = res.threat_score;

        // Reset classes and set threat color indicators dynamically
        scoreCircle.className = 'w-full h-full rounded-full border-4 flex items-center justify-center text-3xl font-extrabold font-mono text-white transition-all duration-300';
        if (res.threat_score >= 75) {
            scoreCircle.classList.add('border-red-500/80', 'shadow-lg', 'shadow-red-500/10');
        } else if (res.threat_score >= 40) {
            scoreCircle.classList.add('border-amber-500/80', 'shadow-lg', 'shadow-amber-500/10');
        } else {
            scoreCircle.classList.add('border-blue-500/80', 'shadow-lg', 'shadow-blue-500/10');
        }

        // Status badge
        const badge = document.getElementById('investigator-status-badge');
        badge.textContent = res.status;
        badge.className = 'text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-wider border';
        if (res.status === 'MALICIOUS') {
            badge.classList.add('bg-red-500/10', 'text-red-400', 'border-red-500/20');
        } else if (res.status === 'SUSPICIOUS') {
            badge.classList.add('bg-amber-500/10', 'text-amber-400', 'border-amber-500/20');
        } else {
            badge.classList.add('bg-blue-500/10', 'text-blue-400', 'border-blue-500/20');
        }

        // 2. Metadata Fill
        document.getElementById('intel-type').textContent = res.type;
        document.getElementById('intel-isp').textContent = `${res.geoip.isp} (${res.geoip.asn})`;
        document.getElementById('intel-geo').textContent = `${res.geoip.city}, ${res.geoip.country} (${res.geoip.country_code})`;

        // CVE chips
        const cvesContainer = document.getElementById('intel-cves');
        cvesContainer.innerHTML = '';
        if (res.cves && res.cves.length > 0) {
            res.cves.forEach(cve => {
                const span = document.createElement('span');
                span.className = 'inline-block bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded text-[10px] font-bold mr-1.5 mb-1.5';
                span.textContent = cve;
                cvesContainer.appendChild(span);
            });
        } else {
            cvesContainer.textContent = 'None identified';
        }

        // 3. Actors chips
        const actorsContainer = document.getElementById('intel-actors');
        actorsContainer.innerHTML = '';
        if (res.threat_actors && res.threat_actors.length > 0) {
            res.threat_actors.forEach(act => {
                const span = document.createElement('span');
                span.className = 'inline-block bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2.5 py-1 rounded text-xs font-semibold mr-1.5 mb-1.5';
                span.textContent = act;
                actorsContainer.appendChild(span);
            });
        } else {
            actorsContainer.innerHTML = '<span class="text-slate-500 italic text-xs">No known threat groups associated.</span>';
        }

        // 4. Open ports
        const portsContainer = document.getElementById('intel-ports');
        portsContainer.innerHTML = '';
        if (res.open_ports && res.open_ports.length > 0) {
            res.open_ports.forEach(port => {
                const span = document.createElement('span');
                span.className = 'inline-block bg-slate-800 text-slate-300 border border-slate-700 px-2 py-0.5 rounded text-xs font-medium mr-1.5 mb-1.5';
                span.textContent = port;
                portsContainer.appendChild(span);
            });
        } else {
            portsContainer.innerHTML = '<span class="text-slate-500 text-xs">No scanned open ports.</span>';
        }

        // 5. Database cross references
        const tableBody = document.getElementById('investigator-table-body');
        tableBody.innerHTML = '';

        if (res.related_alerts && res.related_alerts.length > 0) {
            res.related_alerts.forEach(alert => {
                const tr = document.createElement('tr');
                tr.className = 'border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors cursor-pointer';

                let bClass = 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
                if (alert.severity === 'HIGH') bClass = 'bg-red-500/10 text-red-400 border border-red-500/20';
                if (alert.severity === 'MEDIUM') bClass = 'bg-amber-500/10 text-amber-400 border border-amber-500/20';

                tr.innerHTML = `
                    <td class="px-4 py-3 font-mono font-bold text-slate-400">#${alert.id}</td>
                    <td class="px-4 py-3 text-slate-400 whitespace-nowrap">${alert.detected_at}</td>
                    <td class="px-4 py-3 font-semibold text-slate-200">${escapeHTML(alert.source)}</td>
                    <td class="px-4 py-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${bClass}">${alert.severity}</span></td>
                    <td class="px-4 py-3 font-mono text-slate-300 text-xs">${escapeHTML(alert.matched_keyword)}</td>
                `;

                // Allow view modal on double click/row click
                tr.addEventListener('dblclick', () => showDetailsModal(alert));
                tr.style.cursor = 'pointer';

                tableBody.appendChild(tr);
            });
        } else {
            tableBody.innerHTML = `
                <tr>
                    <td colspan="5" class="px-4 py-6 text-center text-slate-500 text-xs">
                        No related leak records identified in the ThreatIntel database.
                    </td>
                </tr>
            `;
        }
    } catch (error) {
        console.error("OSINT investigation query failed:", error);
        alert("Error executing intelligence trace query.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-fingerprint"></i> Analyze Target`;
    }
}

// Collapsible Sidebar toggling handler
function toggleSidebarState() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');
    const toggleIcon = document.getElementById('sidebar-toggle-icon');
    const textElements = document.querySelectorAll('.nav-text, .logo-text, .sub-logo, .sidebar-footer-brand');

    const isCollapsed = sidebar.classList.contains('w-[72px]');
    
    if (!isCollapsed) {
        // Collapse it
        sidebar.classList.remove('w-64', 'px-4');
        sidebar.classList.add('w-[72px]', 'px-2');
        mainContent.classList.remove('ml-64');
        mainContent.classList.add('ml-[72px]');
        if (toggleIcon) toggleIcon.classList.add('rotate-180');
        textElements.forEach(el => el.classList.add('hidden'));
        
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.add('justify-center', 'px-0');
        });
        document.querySelector('.logo-container').classList.add('justify-center');
        localStorage.setItem('sidebar_collapsed', 'true');
    } else {
        // Expand it
        sidebar.classList.remove('w-[72px]', 'px-2');
        sidebar.classList.add('w-64', 'px-4');
        mainContent.classList.remove('ml-[72px]');
        mainContent.classList.add('ml-64');
        if (toggleIcon) toggleIcon.classList.remove('rotate-180');
        textElements.forEach(el => el.classList.remove('hidden'));
        
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.remove('justify-center', 'px-0');
        });
        document.querySelector('.logo-container').classList.remove('justify-center');
        localStorage.setItem('sidebar_collapsed', 'false');
    }

    // Trigger Chart.js resizes after the CSS transition ends (300ms)
    setTimeout(() => {
        if (chartSeverity) chartSeverity.resize();
        if (chartSources) chartSources.resize();
    }, 310);
}

// Load persisted sidebar state on DOM load
function applyPersistedSidebarState() {
    const isCollapsed = localStorage.getItem('sidebar_collapsed') === 'true';
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');
    const toggleIcon = document.getElementById('sidebar-toggle-icon');
    const textElements = document.querySelectorAll('.nav-text, .logo-text, .sub-logo, .sidebar-footer-brand');
    
    if (isCollapsed) {
        sidebar.classList.remove('w-64', 'px-4');
        sidebar.classList.add('w-[72px]', 'px-2');
        mainContent.classList.remove('ml-64');
        mainContent.classList.add('ml-[72px]');
        if (toggleIcon) toggleIcon.classList.add('rotate-180');
        textElements.forEach(el => el.classList.add('hidden'));
        
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.add('justify-center', 'px-0');
        });
        document.querySelector('.logo-container').classList.add('justify-center');
    } else {
        sidebar.classList.remove('w-[72px]', 'px-2');
        sidebar.classList.add('w-64', 'px-4');
        mainContent.classList.remove('ml-[72px]');
        mainContent.classList.add('ml-64');
        if (toggleIcon) toggleIcon.classList.remove('rotate-180');
        textElements.forEach(el => el.classList.remove('hidden'));
        
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.remove('justify-center', 'px-0');
        });
        document.querySelector('.logo-container').classList.remove('justify-center');
    }
    
    // Force chart resize check on boot
    setTimeout(() => {
        if (chartSeverity) chartSeverity.resize();
        if (chartSources) chartSources.resize();
    }, 310);
}

// Toggle Webhook URL visibility (eye icon handler)
function toggleWebhookVisibility() {
    const urlInput = document.getElementById('webhook-url');
    const visibilityBtn = document.getElementById('btn-toggle-webhook-visibility');
    const icon = visibilityBtn.querySelector('i');
    
    if (urlInput.type === 'password') {
        urlInput.type = 'text';
        icon.className = 'fa-solid fa-eye';
    } else {
        urlInput.type = 'password';
        icon.className = 'fa-solid fa-eye-slash';
    }
}

// Running UTC Clock (standard SOC feature)
function startUTCClock() {
    const clockEl = document.getElementById('utc-clock');
    if (!clockEl) return;
    const updateTime = () => {
        const now = new Date();
        const timeString = now.toISOString().slice(11, 19) + ' UTC';
        clockEl.textContent = timeString;
    };
    updateTime();
    setInterval(updateTime, 1000);
}
