// ================= CORE DATA =================
let scanHistory = [];
let vectorChart = null;
let currentChartType = 'bar'; // Default view for Analytics

// ================= INITIALIZATION =================
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    loadData();
});

/**
 * Loads forensic data from Chrome storage and triggers UI refresh
 */
function loadData() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['scanHistory'], (res) => {
            scanHistory = res.scanHistory || [];
            console.log(`📊 [Dashboard] Loaded ${scanHistory.length} forensic records.`);
            refreshUI();
        });
    }
}

/**
 * Updates all widgets and charts with the latest storage data
 */
function refreshUI() {
    updateStats();
    updateActivityTable();
    updateAiInsights();
    initCharts(); // Initialize Overview charts
}

// ================= NAVIGATION =================
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            
            // UI State Management
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            const sectionId = 'section-' + item.dataset.section;
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.getElementById(sectionId).classList.add('active');

            // Update Header Title
            document.getElementById('pageTitle').textContent = item.textContent.trim();

            // Lazy Load specialized components
            if (item.dataset.section === 'analytics') {
                // Short delay to allow DOM transition before Chart.js renders
                setTimeout(() => initVectorChart(), 50);
            }
            if (item.dataset.section === 'geo') initMap();
        });
    });
}

// ================= WIDGET LOGIC =================

/**
 * Calculates real-time stats based on Judge Agent's scores
 */
function updateStats() {
    const total = scanHistory.length;
    const phish = scanHistory.filter(s => s.final_risk_score >= 70).length;
    const safe = scanHistory.filter(s => s.final_risk_score < 40).length;
    const rate = total > 0 ? ((safe / total) * 100).toFixed(1) : 100;

    document.getElementById('statTotal').textContent = total.toLocaleString();
    document.getElementById('statPhish').textContent = phish;
    document.getElementById('statSafe').textContent = safe;
    document.getElementById('statRate').textContent = rate + '%';
}

/**
 * Renders interactive activity log. Clicking a row opens that email's report.
 */
function updateActivityTable() {
    const tbody = document.getElementById('activityTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    // Show most recent scans first
    scanHistory.slice().reverse().forEach(entry => {
        const score = entry.final_risk_score || 0;
        const status = score >= 70 ? 'red' : score >= 40 ? 'yellow' : 'green';
        
        const row = document.createElement('tr');
        row.style.cursor = 'pointer';
        row.innerHTML = `
            <td>${entry.date || 'Recent'}</td>
            <td>${entry.subject}</td>
            <td>${entry.sender.split('<')[0]}</td>
            <td class="${status}">${score}%</td>
            <td><span class="pill ${status}">${status.toUpperCase()}</span></td>
        `;

        // Redirect to the individual report view
        row.addEventListener('click', () => {
            chrome.storage.local.set({ lastReport: entry }, () => {
                window.location.href = 'report.html';
            });
        });

        tbody.appendChild(row);
    });
}

function updateAiInsights() {
    const container = document.getElementById('aiInsightsGrid');
    if (!container) return;
    
    const threats = scanHistory.filter(s => s.final_risk_score >= 70).slice(0, 3);
    
    if (threats.length === 0) {
        container.innerHTML = '<div class="card ai-card"><div class="ai-card-body">No active threats detected in history.</div></div>';
        return;
    }

    container.innerHTML = threats.map(t => `
        <div class="card ai-card">
            <div class="card-title">Threat Detected</div>
            <div class="ai-card-body">${t.user_friendly_summary}</div>
            <div class="pill red" style="margin-top:10px; width:fit-content">CRITICAL</div>
        </div>
    `).join('');
}

// ================= CHARTING (VECTOR ANALYSIS) =================

/**
 * Initializes the specialized Forensic Vector Chart
 */
function initVectorChart() {
    const canvas = document.getElementById('vectorChart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    if (vectorChart) vectorChart.destroy();

    vectorChart = new Chart(ctx, {
        type: currentChartType,
        data: {
            labels: scanHistory.map((_, i) => `Scan ${i+1}`),
            datasets: [
                {
                    label: 'DNA (Auth)',
                    data: scanHistory.map(s => s.dna_evidence?.auth_score || 0),
                    backgroundColor: '#ff4d4d',
                    borderColor: '#ff4d4d',
                    tension: 0.3
                },
                {
                    label: 'Links (Typosquat)',
                    data: scanHistory.map(s => s.link_evidence?.link_risk_score || 0),
                    backgroundColor: '#ffd60a',
                    borderColor: '#ffd60a',
                    tension: 0.3
                },
                {
                    label: 'Profiling (Social)',
                    data: scanHistory.map(s => s.behavioral_evidence?.manipulation_score || 0),
                    backgroundColor: '#30d158',
                    borderColor: '#30d158',
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { stacked: currentChartType === 'bar' },
                y: { stacked: currentChartType === 'bar', beginAtZero: true, max: currentChartType === 'bar' ? undefined : 100 }
            },
            plugins: { legend: { display: true, position: 'bottom' } }
        }
    });

    // Only set up listeners once
    if (!window.chartListenersInit) {
        setupVectorControls();
        window.chartListenersInit = true;
    }
}

function setupVectorControls() {
    // Switch between Bar and Line
    document.getElementById('toggleChartType').addEventListener('click', (e) => {
        currentChartType = currentChartType === 'bar' ? 'line' : 'bar';
        e.target.textContent = `Switch to ${currentChartType === 'bar' ? 'Line Graph' : 'Bar Chart'}`;
        initVectorChart();
    });

    // Vector Visibility Toggles
    document.querySelectorAll('.vector-toggle input').forEach((cb, index) => {
        cb.addEventListener('change', () => {
            const checked = Array.from(document.querySelectorAll('.vector-toggle input')).filter(c => c.checked);
            if (checked.length === 0) {
                cb.checked = true; // "At Least One" Rule
                return;
            }
            vectorChart.setDatasetVisibility(index, cb.checked);
            vectorChart.update();
        });
    });
}

function initCharts() {
    // Overview Line Chart (Risk Score History)
    const ctx = document.getElementById('lineChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: scanHistory.map((_, i) => i + 1),
            datasets: [{
                label: 'Risk Score',
                data: scanHistory.map(s => s.final_risk_score),
                borderColor: '#ff4d4d',
                backgroundColor: 'rgba(255, 77, 77, 0.1)',
                fill: true
            }]
        }
    });
}

let map = null;
function initMap() {
    if (map) return;
    map = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);
}