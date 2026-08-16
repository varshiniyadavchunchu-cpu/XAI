// ==========================================================================
// XAI-IDS Frontend Application Logic
// ==========================================================================

// Global State
let currentTab = 'dashboard';
let snifferInterval = null;
let snifferRunning = false;
let modelTrained = false;
let trafficChartInstance = null;
let featureChartInstance = null;
let trafficHistory = []; // To feed the dashboard volume graph
let capturedFlows = []; // Local cache of captured network flows to prevent race conditions
const API_URL = ''; // Same origin

// Presets mapping for Manual Analyzer
const FORM_PRESETS = {
    benign: {
        "Destination Port": 443, "Flow Duration": 2.35, "Total Fwd Packets": 12, "Total Backward Packets": 10,
        "Total Length of Fwd Packets": 540, "Total Length of Bwd Packets": 980, "Fwd Packet Length Max": 130,
        "Fwd Packet Length Min": 0, "Fwd Packet Length Mean": 45.0, "Bwd Packet Length Max": 230,
        "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 98.0, "Flow Bytes/s": 646.8, "Flow Packets/s": 9.36,
        "Flow IAT Mean": 0.11, "Flow IAT Max": 0.85, "Fwd Header Length": 240, "Bwd Header Length": 200,
        "Packet Length Mean": 69.09, "Average Packet Size": 72.54
    },
    doshulk: {
        "Destination Port": 80, "Flow Duration": 35.4, "Total Fwd Packets": 1850, "Total Backward Packets": 4,
        "Total Length of Fwd Packets": 985000, "Total Length of Bwd Packets": 240, "Fwd Packet Length Max": 1100,
        "Fwd Packet Length Min": 320, "Fwd Packet Length Mean": 532.4, "Bwd Packet Length Max": 60,
        "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 60.0, "Flow Bytes/s": 27831.6, "Flow Packets/s": 52.37,
        "Flow IAT Mean": 0.019, "Flow IAT Max": 0.22, "Fwd Header Length": 37000, "Bwd Header Length": 80,
        "Packet Length Mean": 531.4, "Average Packet Size": 531.4
    },
    ddos: {
        "Destination Port": 48293, "Flow Duration": 0.045, "Total Fwd Packets": 38, "Total Backward Packets": 1,
        "Total Length of Fwd Packets": 1650, "Total Length of Bwd Packets": 40, "Fwd Packet Length Max": 80,
        "Fwd Packet Length Min": 20, "Fwd Packet Length Mean": 43.42, "Bwd Packet Length Max": 40,
        "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 40.0, "Flow Bytes/s": 37555.5, "Flow Packets/s": 866.6,
        "Flow IAT Mean": 0.0011, "Flow IAT Max": 0.012, "Fwd Header Length": 760, "Bwd Header Length": 20,
        "Packet Length Mean": 43.33, "Average Packet Size": 43.33
    },
    portscan: {
        "Destination Port": 23, "Flow Duration": 0.0008, "Total Fwd Packets": 1, "Total Backward Packets": 0,
        "Total Length of Fwd Packets": 0, "Total Length of Bwd Packets": 0, "Fwd Packet Length Max": 0,
        "Fwd Packet Length Min": 0, "Fwd Packet Length Mean": 0.0, "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0, "Bwd Packet Length Mean": 0.0, "Flow Bytes/s": 0.0, "Flow Packets/s": 1250.0,
        "Flow IAT Mean": 0.0008, "Flow IAT Max": 0.0008, "Fwd Header Length": 20, "Bwd Header Length": 0,
        "Packet Length Mean": 0.0, "Average Packet Size": 0.0
    },
    ssh: {
        "Destination Port": 22, "Flow Duration": 1.25, "Total Fwd Packets": 18, "Total Backward Packets": 15,
        "Total Length of Fwd Packets": 1152, "Total Length of Bwd Packets": 960, "Fwd Packet Length Max": 64,
        "Fwd Packet Length Min": 20, "Fwd Packet Length Mean": 64.0, "Bwd Packet Length Max": 64,
        "Bwd Packet Length Min": 20, "Bwd Packet Length Mean": 64.0, "Flow Bytes/s": 1689.6, "Flow Packets/s": 26.4,
        "Flow IAT Mean": 0.037, "Flow IAT Max": 0.65, "Fwd Header Length": 360, "Bwd Header Length": 300,
        "Packet Length Mean": 64.0, "Average Packet Size": 64.0
    },
    web: {
        "Destination Port": 8080, "Flow Duration": 4.82, "Total Fwd Packets": 22, "Total Backward Packets": 20,
        "Total Length of Fwd Packets": 18500, "Total Length of Bwd Packets": 4800, "Fwd Packet Length Max": 1850,
        "Fwd Packet Length Min": 240, "Fwd Packet Length Mean": 840.9, "Bwd Packet Length Max": 420,
        "Bwd Packet Length Min": 40, "Bwd Packet Length Mean": 240.0, "Flow Bytes/s": 4834.0, "Flow Packets/s": 8.71,
        "Flow IAT Mean": 0.114, "Flow IAT Max": 3.25, "Fwd Header Length": 440, "Bwd Header Length": 400,
        "Packet Length Mean": 554.7, "Average Packet Size": 554.7
    }
};

// Initial App Setup
document.addEventListener("DOMContentLoaded", () => {
    updateTime();
    setInterval(updateTime, 1000);
    
    checkSystemStatus();
    setInterval(checkSystemStatus, 6000); // Check server health every 6s
    
    initDashboardChart();
    loadPreset(); // Pre-fill manual analyzer
});

// System Clock
function updateTime() {
    const timeEl = document.getElementById("system-time");
    if (timeEl) {
        const now = new Date();
        timeEl.textContent = now.toLocaleTimeString();
    }
}

// Tab switcher
function switchTab(tabId) {
    currentTab = tabId;
    
    // Switch Buttons
    document.querySelectorAll(".nav-btn").forEach(btn => btn.classList.remove("active"));
    const activeBtn = document.getElementById(`tab-${tabId}-btn`);
    if (activeBtn) activeBtn.classList.add("active");
    
    // Switch Views
    document.querySelectorAll(".tab-view").forEach(view => view.classList.remove("active"));
    const activeView = document.getElementById(`tab-${tabId}`);
    if (activeView) activeView.classList.add("active");
    
    // Header Title
    const titles = {
        dashboard: "Security Dashboard",
        sniffer: "Live Traffic Sniffer",
        manual: "Manual Flow Analyzer",
        model: "Model Performance & Metrics"
    };
    document.getElementById("page-title").textContent = titles[tabId] || "Intrusion Detection System";
    
}

// Check backend status
async function checkSystemStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        
        // Status Dot & Indicator
        const dot = document.getElementById("status-dot");
        const txt = document.getElementById("status-text");
        
        if (data.status === "online") {
            dot.className = "status-dot green";
            txt.textContent = "API: Connected";
        } else {
            dot.className = "status-dot red";
            txt.textContent = "API: Offline";
        }
        
        // Model Indicator
        const modelTxt = document.getElementById("model-status-text");
        modelTrained = data.model_trained;
        if (modelTrained) {
            modelTxt.textContent = "Classifier: Trained";
            modelTxt.parentElement.querySelector("i").className = "fa-solid fa-brain text-green";
            // Attempt to load metrics if not already done
            loadModelMetrics();
        } else {
            modelTxt.textContent = "Classifier: Untrained";
            modelTxt.parentElement.querySelector("i").className = "fa-solid fa-brain text-red";
        }
        
        // Synchronize Sniffer states
        snifferRunning = data.sniffer_running;
        updateSnifferUI();
        
        // Synchronize Simulate Attacks checkbox state
        const chkAttacks = document.getElementById("chk-simulate-attacks");
        if (chkAttacks && data.simulate_attacks !== undefined) {
            chkAttacks.checked = data.simulate_attacks;
        }
        
    } catch (e) {
        console.error("Connection error checking status:", e);
        const dot = document.getElementById("status-dot");
        const txt = document.getElementById("status-text");
        dot.className = "status-dot red";
        txt.textContent = "API: Disconnected";
        
        const modelTxt = document.getElementById("model-status-text");
        modelTxt.textContent = "Classifier: Disconnected";
    }
}

// Chart Initializations
function initDashboardChart() {
    const ctx = document.getElementById('trafficVolumeChart').getContext('2d');
    
    // Generate empty history labels/data
    const labels = Array.from({length: 15}, (_, i) => '');
    const dataPoints = Array.from({length: 15}, () => 0);
    
    trafficChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Flows/Sec',
                data: dataPoints,
                borderColor: '#06b6d4',
                backgroundColor: 'rgba(6, 182, 212, 0.05)',
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointRadius: 2,
                pointHoverRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: { display: false },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.03)' },
                    ticks: { color: '#64748b', font: { family: 'JetBrains Mono' } }
                }
            }
        }
    });
}

function updateDashboardChart(flowCount) {
    if (!trafficChartInstance) return;
    
    // Add value, slide window
    trafficChartInstance.data.datasets[0].data.push(flowCount);
    trafficChartInstance.data.datasets[0].data.shift();
    
    // Dummy labels just to force layout
    trafficChartInstance.data.labels.push('');
    trafficChartInstance.data.labels.shift();
    
    trafficChartInstance.update('none');
}

// Model Performance module
async function loadModelMetrics() {
    if (!modelTrained) return;
    
    try {
        const res = await fetch('/api/metrics');
        if (!res.ok) return;
        const data = await res.json();
        
        // Update Stats
        const accEl = document.getElementById("stats-accuracy");
        if (accEl) accEl.textContent = (data.accuracy * 100).toFixed(1) + "%";
        
        // Render Model Dashboard Performance
        renderModelDashboard(data);
    } catch (e) {
        console.error("Error loading model metrics:", e);
    }
}

function renderModelDashboard(metrics) {
    const container = document.getElementById("model-dashboard-panel");
    if (!container) return;
    
    // We construct columns for metrics, confusion matrix, and feature importances
    let classRowsHtml = '';
    for (const [cls, vals] of Object.entries(metrics.class_metrics)) {
        classRowsHtml += `
            <tr>
                <td style="font-weight:600;">${cls}</td>
                <td class="td-mono">${(vals.precision * 100).toFixed(1)}%</td>
                <td class="td-mono">${(vals.recall * 100).toFixed(1)}%</td>
                <td class="td-mono">${(vals.f1 * 100).toFixed(1)}%</td>
                <td class="td-mono">${vals.support}</td>
            </tr>
        `;
    }
    
    // Compute confusion matrix HTML grid
    const cm = metrics.confusion_matrix;
    const classes = metrics.classes;
    let cmHtml = '<div class="cm-labels-header">';
    classes.forEach(c => {
        // Shorter labels for headers
        const short = c.length > 8 ? c.substring(0, 7) + '.' : c;
        cmHtml += `<span>${short}</span>`;
    });
    cmHtml += '</div><div class="cm-container">';
    
    for (let r = 0; r < cm.length; r++) {
        cmHtml += '<div class="cm-row">';
        for (let c = 0; c < cm[r].length; c++) {
            const val = cm[r][c];
            // Compute visual class depending on correct (diagonal) vs incorrect
            let levelClass = 'cm-lvl-0';
            if (r === c) {
                // Correct classification
                if (val > 500) levelClass = 'cm-lvl-4';
                else if (val > 100) levelClass = 'cm-lvl-3';
                else if (val > 20) levelClass = 'cm-lvl-2';
                else if (val > 0) levelClass = 'cm-lvl-1';
            } else {
                // Misclassification
                if (val > 10) levelClass = 'cm-err-3';
                else if (val > 2) levelClass = 'cm-err-2';
                else if (val > 0) levelClass = 'cm-err-1';
            }
            
            cmHtml += `
                <div class="cm-cell ${levelClass}">
                    <span class="cm-cell-val">${val}</span>
                    <div class="cm-tooltip">True: ${classes[r]}<br>Pred: ${classes[c]}<br>Count: ${val}</div>
                </div>
            `;
        }
        cmHtml += '</div>';
    }
    cmHtml += '</div>';
    
    container.innerHTML = `
        <!-- Main Stats -->
        <div class="card padding-lg model-metric-card glow-cyan">
            <span class="model-metric-val">${(metrics.accuracy * 100).toFixed(2)}%</span>
            <span class="model-metric-lbl">Accuracy</span>
        </div>
        <div class="card padding-lg model-metric-card glow-blue">
            <span class="model-metric-val">${(metrics.precision * 100).toFixed(2)}%</span>
            <span class="model-metric-lbl">Weighted Precision</span>
        </div>
        <div class="card padding-lg model-metric-card glow-amber">
            <span class="model-metric-val">${(metrics.recall * 100).toFixed(2)}%</span>
            <span class="model-metric-lbl">Weighted Recall</span>
        </div>
        <div class="card padding-lg model-metric-card glow-red">
            <span class="model-metric-val">${(metrics.f1 * 100).toFixed(2)}%</span>
            <span class="model-metric-lbl">Weighted F1-Score</span>
        </div>
        
        <!-- Detailed Table -->
        <div class="card padding-lg model-plot-card" style="grid-column: span 7;">
            <div class="card-header border-bottom">
                <h2>Class-wise Diagnostics</h2>
            </div>
            <div class="table-container" style="max-height: 250px; margin-top: 15px;">
                <table>
                    <thead>
                        <tr>
                            <th>Class</th>
                            <th>Precision</th>
                            <th>Recall</th>
                            <th>F1-Score</th>
                            <th>Support</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${classRowsHtml}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Confusion Matrix -->
        <div class="card padding-lg model-plot-card" style="grid-column: span 5;">
            <div class="card-header border-bottom">
                <h2>Confusion Matrix</h2>
            </div>
            ${cmHtml}
            <div class="cm-axis-label">Columns: Predicted // Rows: Actual</div>
        </div>
        
        <!-- Feature Importance Plot -->
        <div class="card padding-lg" style="grid-column: span 12; min-height: 380px;">
            <div class="card-header border-bottom">
                <h2>Random Forest Feature Importances</h2>
                <span class="card-subtitle">Contribution of top features to tree branching split</span>
            </div>
            <div style="height: 280px; margin-top: 15px; position:relative;">
                <canvas id="featureImportanceChart"></canvas>
            </div>
        </div>
    `;
    
    // Render Feature Importance Chart
    setTimeout(() => {
        const fCtx = document.getElementById("featureImportanceChart").getContext('2d');
        const top10 = metrics.feature_importances.slice(0, 10);
        
        featureChartInstance = new Chart(fCtx, {
            type: 'bar',
            data: {
                labels: top10.map(x => x.feature),
                datasets: [{
                    label: 'Importance Value',
                    data: top10.map(x => x.importance),
                    backgroundColor: 'rgba(6, 182, 212, 0.45)',
                    borderColor: '#06b6d4',
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono' } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#f8fafc', font: { family: 'Outfit', weight: '500' } }
                    }
                }
            }
        });
    }, 100);
}

// Retrain Model action
async function trainModel() {
    const btn = document.getElementById("btn-train-model");
    const loader = btn.querySelector("i");
    
    btn.disabled = true;
    loader.className = "fa-solid fa-gears fa-spin";
    btn.lastChild.textContent = " Training Random Forest...";
    
    try {
        const res = await fetch('/api/train', { method: 'POST' });
        const data = await res.json();
        
        if (data.success) {
            modelTrained = true;
            document.getElementById("model-status-text").textContent = "Classifier: Trained";
            document.getElementById("model-status-text").parentElement.querySelector("i").className = "fa-solid fa-brain text-green";
            
            // Reload metrics
            renderModelDashboard(data.metrics);
            
            // Update dashboard accuracy card
            const accEl = document.getElementById("stats-accuracy");
            if (accEl) accEl.textContent = (data.metrics.accuracy * 100).toFixed(1) + "%";
            
            alert("Model training completed successfully! Diagnostics and SHAP explainer have been re-initialized.");
        } else {
            alert("Training failed: " + data.message);
        }
    } catch (e) {
        console.error("Training request failed:", e);
        alert("Training request failed. Verify API is active.");
    } finally {
        btn.disabled = false;
        loader.className = "fa-solid fa-gears animate-spin-hover";
        btn.lastChild.textContent = " Retrain Random Forest";
    }
}

// Presets Loading
function loadPreset() {
    const preset = document.getElementById("preset-select").value;
    const vals = FORM_PRESETS[preset];
    if (!vals) return;
    
    for (const [col, val] of Object.entries(vals)) {
        // Map feature name to ID convention
        const id = mapColToId(col);
        const el = document.getElementById(id);
        if (el) el.value = val;
    }
}

function mapColToId(colName) {
    const mapping = {
        'Destination Port': 'm-port',
        'Flow Duration': 'm-duration',
        'Total Fwd Packets': 'm-fwd-pkts',
        'Total Backward Packets': 'm-bwd-pkts',
        'Total Length of Fwd Packets': 'm-fwd-len',
        'Total Length of Bwd Packets': 'm-bwd-len',
        'Fwd Packet Length Max': 'm-fwd-max',
        'Fwd Packet Length Min': 'm-fwd-min',
        'Fwd Packet Length Mean': 'm-fwd-mean',
        'Bwd Packet Length Max': 'm-bwd-max',
        'Bwd Packet Length Min': 'm-bwd-min',
        'Bwd Packet Length Mean': 'm-bwd-mean',
        'Flow Bytes/s': 'm-bytes-s',
        'Flow Packets/s': 'm-pkts-s',
        'Flow IAT Mean': 'm-iat-mean',
        'Flow IAT Max': 'm-iat-max',
        'Fwd Header Length': 'm-fwd-header',
        'Bwd Header Length': 'm-bwd-header',
        'Packet Length Mean': 'm-pkt-mean',
        'Average Packet Size': 'm-pkt-size'
    };
    return mapping[colName] || '';
}

// Sniffer toggle
async function toggleSniffer() {
    const btn = document.getElementById("btn-toggle-sniffer");
    const badge = document.getElementById("sniffer-badge");
    
    if (snifferRunning) {
        // Stop
        try {
            const res = await fetch('/api/sniff/stop', { method: 'POST' });
            if (res.ok) {
                snifferRunning = false;
                clearInterval(snifferInterval);
                snifferInterval = null;
                updateSnifferUI();
            }
        } catch (e) {
            console.error("Error stopping sniffer:", e);
        }
    } else {
        // Start
        try {
            const res = await fetch('/api/sniff/start', { method: 'POST' });
            if (res.ok) {
                snifferRunning = true;
                snifferInterval = setInterval(fetchTraffic, 1500);
                updateSnifferUI();
            }
        } catch (e) {
            console.error("Error starting sniffer:", e);
        }
    }
}

function updateSnifferUI() {
    const btn = document.getElementById("btn-toggle-sniffer");
    const badge = document.getElementById("sniffer-badge");
    const info = document.getElementById("sniffer-status-info");
    const tblContainer = document.querySelector(".table-container");
    
    if (!btn || !badge) return;
    
    if (snifferRunning) {
        btn.className = "btn btn-danger";
        btn.innerHTML = `<i class="fa-solid fa-stop"></i> Stop Traffic Sniffing`;
        
        badge.className = "badge bg-active";
        badge.querySelector(".badge-text").textContent = "Sniffer Active";
        
        info.textContent = "Sniffer capturing packet flows in background. Click table rows to generate SHAP interpretations.";
        
        if (tblContainer) tblContainer.classList.add("scanning");
        
        // Start interval if not running (e.g. from page reload)
        if (!snifferInterval) {
            snifferInterval = setInterval(fetchTraffic, 1500);
        }
    } else {
        btn.className = "btn btn-primary";
        btn.innerHTML = `<i class="fa-solid fa-play"></i> Start Traffic Sniffing`;
        
        badge.className = "badge bg-inactive";
        badge.querySelector(".badge-text").textContent = "Sniffer Inactive";
        
        info.textContent = "Sniffer stands ready. Will auto-fallback to simulated stream if driver or privileges are unavailable.";
        
        if (tblContainer) tblContainer.classList.remove("scanning");
        
        if (snifferInterval) {
            clearInterval(snifferInterval);
            snifferInterval = null;
        }
    }
}

// Fetch Traffic data from Sniffer API
let alertCount = 0;
let totalFlows = 0;
let alertsDatabase = [];

async function fetchTraffic() {
    try {
        const res = await fetch('/api/sniff/traffic');
        const data = await res.json();
        
        const flows = data.flows;
        capturedFlows = flows; // Store in local client cache
        totalFlows = totalFlows + flows.length; // Approximate total counters for visualization
        document.getElementById("stats-total-flows").textContent = totalFlows;
        
        // Update Chart with number of incoming flows in this batch
        updateDashboardChart(flows.length);
        
        // Re-render table
        renderTrafficTable(flows);
        
        // Scan for new attacks
        flows.forEach(flow => {
            if (flow.Prediction && flow.Prediction !== 'BENIGN' && flow.Prediction !== 'Model Untrained' && flow.Prediction !== 'Error') {
                // Prevent duplicate alerts (key by flow tuple or timestamp)
                const alertKey = `${flow.Timestamp}_${flow['Source IP']}_${flow.Prediction}`;
                if (!alertsDatabase.includes(alertKey)) {
                    alertsDatabase.push(alertKey);
                    alertCount++;
                    document.getElementById("stats-alerts").textContent = alertCount;
                    
                    // Update highest threat label
                    document.getElementById("stats-highest-threat").textContent = flow.Prediction;
                    
                    // Append Alert to Dashboard Feed
                    addAlertFeedItem(flow);
                }
            }
        });
        
        // Compute active Threat Level Percentage
        const attackFlows = flows.filter(f => f.Prediction && f.Prediction !== 'BENIGN' && f.Prediction !== 'Model Untrained' && f.Prediction !== 'Error').length;
        const totalInBatch = flows.length || 1;
        const threatPct = Math.round((attackFlows / totalInBatch) * 100);
        
        const threatBar = document.getElementById("threat-bar");
        const threatTxt = document.getElementById("threat-text");
        const threatPctEl = document.getElementById("threat-percentage");
        
        if (threatBar && threatTxt && threatPctEl) {
            threatBar.style.width = `${threatPct}%`;
            threatPctEl.textContent = `${threatPct}%`;
            
            if (threatPct > 50) {
                threatTxt.textContent = "CRITICAL BREACH DETECTED";
                threatTxt.className = "threat-level-text text-red animate-pulse";
            } else if (threatPct > 15) {
                threatTxt.textContent = "SUSPICIOUS ACTIVITY";
                threatTxt.className = "threat-level-text text-amber";
            } else {
                threatTxt.textContent = "SECURE";
                threatTxt.className = "threat-level-text text-green";
            }
        }
        
    } catch (e) {
        console.error("Error fetching traffic:", e);
    }
}

// Alert feed rendering
function addAlertFeedItem(flow) {
    const feed = document.getElementById("alerts-feed");
    if (!feed) return;
    
    const emptyState = feed.querySelector(".empty-state");
    if (emptyState) emptyState.remove();
    
    const el = document.createElement("div");
    el.className = "alert-item";
    
    el.innerHTML = `
        <div class="alert-main">
            <div class="alert-title-row">
                <span class="badge bg-threat">${flow.Prediction}</span>
                <span class="alert-title">Source: ${flow['Source IP']}</span>
            </div>
            <span class="alert-desc">Targeted port ${flow['Destination Port']} using protocol ${flow.Protocol}. Flow duration was ${flow['Flow Duration'].toFixed(4)}s.</span>
        </div>
        <span class="alert-time">${flow.Timestamp}</span>
    `;
    
    // Insert at top
    feed.insertBefore(el, feed.firstChild);
    
    // Cap feed items
    if (feed.children.length > 20) {
        feed.removeChild(feed.lastChild);
    }
}

function clearAlerts() {
    alertCount = 0;
    alertsDatabase = [];
    document.getElementById("stats-alerts").textContent = "0";
    document.getElementById("stats-highest-threat").textContent = "-";
    
    const feed = document.getElementById("alerts-feed");
    if (feed) {
        feed.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-check-shield text-green"></i>
                <p>No threats detected. System secure.</p>
            </div>
        `;
    }
    
    // Reset threat bar
    document.getElementById("threat-bar").style.width = "0%";
    document.getElementById("threat-percentage").textContent = "0%";
    document.getElementById("threat-text").textContent = "SECURE";
    document.getElementById("threat-text").className = "threat-level-text text-green";
}

// Render Sniffer Flow Logs
let selectedFlowId = null;
function renderTrafficTable(flows) {
    const tbody = document.getElementById("traffic-tbody");
    if (!tbody) return;
    
    if (flows.length === 0) {
        tbody.innerHTML = `
            <tr class="placeholder-row">
                <td colspan="7" class="text-center text-muted">
                    No traffic captured yet. Keep sniffer active.
                </td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    // Reverse the flows to show newest first, but map each back to its original index in the flows array
    flows.slice().reverse().forEach((flow, reversedIdx) => {
        const idx = flows.length - 1 - reversedIdx;
        const isBenign = flow.Prediction === 'BENIGN';
        const isUntrained = flow.Prediction === 'Model Untrained';
        const isError = flow.Prediction === 'Error';
        
        let predClass = 'bg-inactive';
        if (isBenign) predClass = 'bg-benign';
        else if (isUntrained || isError) predClass = 'bg-inactive';
        else predClass = 'bg-threat';
        
        const flowId = `flow-${idx}`;
        const isSelected = selectedFlowId === flowId;
        
        // Ensure confidence represents percentages nicely
        const confidenceVal = flow.Confidence ? (flow.Confidence * 100).toFixed(1) + "%" : 'N/A';
        
        html += `
            <tr id="${flowId}" class="${isSelected ? 'selected-row' : ''}" onclick="selectTrafficFlow(${idx}, '${flowId}')">
                <td class="td-mono">${flow.Timestamp}</td>
                <td class="td-mono">${flow['Source IP']}</td>
                <td class="td-mono">${flow['Destination IP']}</td>
                <td>${flow.Protocol}</td>
                <td class="td-mono">${flow['Destination Port']}</td>
                <td><span class="badge ${predClass}">${flow.Prediction}</span></td>
                <td class="td-mono">${confidenceVal}</td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// Select flow from log and query explainability
let recentFlowCache = null;
async function selectTrafficFlow(index, elementId) {
    // Select styling
    document.querySelectorAll("#traffic-tbody tr").forEach(r => r.classList.remove("selected-row"));
    const row = document.getElementById(elementId);
    if (row) row.classList.add("selected-row");
    selectedFlowId = elementId;
    
    // Retrieve cached flow data directly from local memory
    try {
        const flow = capturedFlows[index];
        if (!flow) return;
        
        const detailPanel = document.getElementById("sniffer-detail-panel");
        detailPanel.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-spinner fa-spin text-cyan"></i>
                <h3>Running Explainable AI Engine</h3>
                <p>Computing SHAP values against background training datasets. Please hold...</p>
            </div>
        `;
        
        // POST to /api/analyze to trigger prediction + SHAP explainability
        const postRes = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(flow)
        });
        
        if (!postRes.ok) {
            const errData = await postRes.json();
            throw new Error(errData.detail || "Explainability engine error");
        }
        
        const analysis = await postRes.json();
        renderAnalysisOutput(analysis, flow, detailPanel);
        
    } catch (e) {
        console.error("Error analyzing flow:", e);
        document.getElementById("sniffer-detail-panel").innerHTML = `
            <div class="card padding-md bg-danger" style="border-left:4px solid var(--red);">
                <h3 class="text-red"><i class="fa-solid fa-triangle-exclamation"></i> Analysis Failure</h3>
                <p style="font-size:13px; margin-top:8px;">${e.message || "Model must be trained before generating explainability logs."}</p>
            </div>
        `;
    }
}

// Render SHAP graph & Recommendations
function renderAnalysisOutput(analysis, rawFlow, targetContainer) {
    const isBenign = analysis.prediction === 'BENIGN';
    const borderCol = isBenign ? 'rgba(34, 197, 94, 0.4)' : 'rgba(239, 68, 68, 0.4)';
    const textCol = isBenign ? 'text-green' : 'text-red';
    const badgeClass = isBenign ? 'bg-benign' : 'bg-threat';
    
    // Meta variables grid
    const metaHtml = `
        <div class="flow-meta-grid">
            <div class="meta-field"><label>Source IP</label><span>${rawFlow['Source IP'] || 'Local'}</span></div>
            <div class="meta-field"><label>Dest IP</label><span>${rawFlow['Destination IP'] || 'Local'}</span></div>
            <div class="meta-field"><label>Port</label><span>${rawFlow['Destination Port']}</span></div>
            <div class="meta-field"><label>Protocol</label><span>${rawFlow.Protocol || 'TCP'}</span></div>
        </div>
    `;
    
    // SHAP explanation chart construction
    let shapHtml = '<div class="shap-chart">';
    const topContribs = analysis.explanation.contributions.slice(0, 7); // Show top 7 features
    
    // Find absolute maximum shap value to scale bars relative to each other
    const maxShap = Math.max(...topContribs.map(c => Math.abs(c.shap_value))) || 0.001;
    
    topContribs.forEach(c => {
        const isPos = c.shap_value > 0;
        const widthPct = Math.min(100, Math.round((Math.abs(c.shap_value) / maxShap) * 100));
        const barClass = isPos ? 'positive' : 'negative';
        
        // Label indicating which way it pushes: positive pushes towards attack class, negative towards benign
        const pushLabel = isPos ? 'Pushes toward threat' : 'Pushes toward benign';
        
        // Round floats for clean displays
        const formattedRaw = c.raw_value % 1 === 0 ? c.raw_value.toFixed(0) : c.raw_value.toFixed(4);
        const formattedShap = c.shap_value > 0 ? `+${c.shap_value.toFixed(4)}` : c.shap_value.toFixed(4);
        
        shapHtml += `
            <div class="shap-row">
                <div class="shap-label-row">
                    <span class="shap-feat-name">${c.feature} <span class="shap-feat-val">(${formattedRaw})</span></span>
                    <span class="shap-feat-val ${isPos ? 'text-amber' : 'text-green'}" title="${pushLabel}">${formattedShap}</span>
                </div>
                <div class="shap-bar-container">
                    <div class="shap-bar ${barClass}" style="--width: ${widthPct}%"></div>
                </div>
            </div>
        `;
    });
    shapHtml += '</div>';
    
    // Security recommendations actions list
    let recListHtml = '';
    analysis.recommendations.actions.forEach(action => {
        recListHtml += `<li>${action}</li>`;
    });
    
    const recHtml = `
        <div class="rec-section severity-${analysis.recommendations.severity}">
            <div class="rec-header severity-${analysis.recommendations.severity}">
                <i class="fa-solid fa-circle-radiation"></i>
                <h4>Security Response Plan [Severity: ${analysis.recommendations.severity}]</h4>
            </div>
            <div class="rec-summary">${analysis.recommendations.summary}</div>
            <ul class="rec-list">
                ${recListHtml}
            </ul>
        </div>
    `;
    
    targetContainer.innerHTML = `
        <div class="detail-header">
            <span class="badge ${badgeClass}" style="float: right; margin-top: 4px;">${analysis.prediction}</span>
            <h3>Flow Diagnostics</h3>
            <span class="card-subtitle">AI confidence level: ${(analysis.confidence * 100).toFixed(1)}%</span>
        </div>
        
        ${metaHtml}
        
        <div class="xai-section">
            <h4>Explainable AI (XAI) feature impact logs (SHAP)</h4>
            <span class="card-subtitle">Metrics driving classification choice:</span>
            ${shapHtml}
        </div>
        
        ${recHtml}
    `;
}

// Manual Analysis Run
async function runManualAnalysis(event) {
    event.preventDefault();
    
    const resultPanel = document.getElementById("manual-result-panel");
    const btn = document.getElementById("btn-manual-analyze");
    
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Processing Network Vector...`;
    
    resultPanel.innerHTML = `
        <div class="empty-state">
            <i class="fa-solid fa-brain fa-pulse text-cyan"></i>
            <h3>Analyzing Parameters</h3>
            <p>Preprocessing inputs, executing model, and mapping SHAP contributions...</p>
        </div>
    `;
    
    // Construct serialized flow dictionary from inputs
    const form = document.getElementById("manual-analysis-form");
    const formData = new FormData(form);
    
    const flow = {};
    formData.forEach((val, key) => {
        flow[key] = parseFloat(val);
    });
    
    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(flow)
        });
        
        if (!res.ok) {
            const errData = await res.json();
            throw new Error(errData.detail || "Explainability request failed.");
        }
        
        const analysis = await res.json();
        
        // Create simulated labels just to support the UI mapping
        const mockRawFlow = {
            'Source IP': 'Manual Vector',
            'Destination IP': '192.168.1.10',
            'Destination Port': flow['Destination Port'],
            'Protocol': 'TCP'
        };
        
        renderAnalysisOutput(analysis, mockRawFlow, resultPanel);
        
    } catch (e) {
        console.error("Manual analysis error:", e);
        resultPanel.innerHTML = `
            <div class="card padding-md bg-danger" style="border-left:4px solid var(--red);">
                <h3 class="text-red"><i class="fa-solid fa-triangle-exclamation"></i> Analysis Failure</h3>
                <p style="font-size:13px; margin-top:8px;">${e.message || "Model must be trained before generating manual reports."}</p>
            </div>
        `;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-wand-magic-sparkles"></i> Classify & Explain Flow`;
    }
}



// Export captured network traffic to CSV format
function exportTrafficCSV() {
    if (!capturedFlows || capturedFlows.length === 0) {
        alert("No traffic flows captured yet to export.");
        return;
    }
    
    const headers = [
        'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Destination Port',
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Max', 
        'Fwd Header Length', 'Bwd Header Length', 'Packet Length Mean', 
        'Average Packet Size', 'Prediction', 'Confidence'
    ];
    
    // Create CSV rows
    let csvRows = [];
    csvRows.push(headers.join(','));
    
    capturedFlows.forEach(flow => {
        const row = headers.map(header => {
            let val = flow[header];
            if (val === undefined) val = '';
            
            // Format confidence nice percentage
            if (header === 'Confidence' && typeof val === 'number') {
                return (val * 100).toFixed(1) + "%";
            }
            
            // Escape quotes and commas if any
            let valStr = String(val).replace(/"/g, '""');
            if (valStr.includes(',') || valStr.includes('\n') || valStr.includes('"')) {
                valStr = `"${valStr}"`;
            }
            return valStr;
        });
        csvRows.push(row.join(','));
    });
    
    const csvContent = csvRows.join("\n");
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `xai_ids_traffic_export_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link); // Required for FF
    
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}



// Toggle simulated attack injection inside fallback stream
async function toggleSimulatedAttacks(enabled) {
    try {
        const res = await fetch('/api/sniff/toggle_attacks', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
        });
        const data = await res.json();
        if (data.success) {
            console.log("Simulated attacks set to: " + data.simulate_attacks);
        } else {
            console.error("Failed to toggle simulated attacks.");
        }
    } catch (e) {
        console.error("Error sending toggle simulated attacks request:", e);
    }
}




