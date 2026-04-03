// ================= CORE DATA =================
let scanHistory = [];
let charts = {};

// ================= INITIALIZATION =================
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    loadData();
});

function loadData() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['scanHistory'], (res) => {
            scanHistory = res.scanHistory || [];
            refreshUI();
        });
    }
}

function refreshUI() {
    updateStats();
    updateActivityTable();
    updateAiInsights();
    initCharts(); // Initialize or Update Chart.js
}

// ================= NAVIGATION =================
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            item.classList.add('active');

            const sectionId = 'section-' + item.dataset.section;
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.getElementById(sectionId).classList.add('active');

            document.getElementById('pageTitle').textContent = item.textContent.trim();

            if (item.dataset.section === 'geo') initMap();
        });
    });
}

// ================= WIDGET LOGIC =================
// Updates stats based on ACTUAL data from Gemini reports
function updateStats() {
    const total = scanHistory.length;
    // Filters based on the Judge Agent's final_risk_score
    const phish = scanHistory.filter(s => s.final_risk_score >= 70).length;
    const safe = scanHistory.filter(s => s.final_risk_score < 40).length;
    const rate = total > 0 ? ((safe / total) * 100).toFixed(1) : 100;

    document.getElementById('statTotal').textContent = total;
    document.getElementById('statPhish').textContent = phish;
    document.getElementById('statSafe').textContent = safe;
    document.getElementById('statRate').textContent = rate + '%';
}

// Makes the activity log interactive
function updateActivityTable() {
    const tbody = document.getElementById('activityTableBody');
    tbody.innerHTML = '';

    scanHistory.slice().reverse().forEach(entry => {
        const score = entry.final_risk_score || 0;
        const status = score >= 70 ? 'red' : score >= 40 ? 'yellow' : 'green';
        
        const row = document.createElement('tr');
        row.style.cursor = 'pointer'; // Visual cue for interactivity
        row.innerHTML = `
            <td>${entry.date || 'Today'}</td>
            <td>${entry.subject}</td>
            <td>${entry.sender.split('<')[0]}</td>
            <td class="${status}">${score}%</td>
            <td><span class="pill ${status}">${status.toUpperCase()}</span></td>
        `;

        // CLICK HANDLER: Redirects to the deep-dive report for THIS specific email
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
    const threats = scanHistory.filter(s => s.final_risk_score >= 70).slice(0, 3);
    
    if (threats.length === 0) {
        container.innerHTML = '<div class="card ai-card"><div class="ai-card-body">System currently clean. No active threats detected.</div></div>';
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

// ================= CHARTS & MAPS =================
function initCharts() {
    const ctxLine = document.getElementById('lineChart').getContext('2d');
    const ctxDoughnut = document.getElementById('doughnutChart').getContext('2d');

    // Destroy existing charts if refreshing
    if (charts.line) charts.line.destroy();
    if (charts.doughnut) charts.doughnut.destroy();

    charts.line = new Chart(ctxLine, {
        type: 'line',
        data: {
            labels: scanHistory.map((_, i) => `Scan ${i+1}`),
            datasets: [{
                label: 'Risk Score',
                data: scanHistory.map(s => s.final_risk_score),
                borderColor: '#ff4d4d',
                tension: 0.4,
                fill: true,
                backgroundColor: 'rgba(255, 77, 77, 0.1)'
            }]
        }
    });

    charts.doughnut = new Chart(ctxDoughnut, {
        type: 'doughnut',
        data: {
            labels: ['Phish', 'Suspicious', 'Safe'],
            datasets: [{
                data: [
                    scanHistory.filter(s => s.final_risk_score >= 70).length,
                    scanHistory.filter(s => s.final_risk_score >= 40 && s.final_risk_score < 70).length,
                    scanHistory.filter(s => s.final_risk_score < 40).length
                ],
                backgroundColor: ['#ff4d4d', '#ffd60a', '#30d158'],
                borderWidth: 0
            }]
        }
    });

    if (vectorChart) vectorChart.destroy();
    initVectorChart();
}

let map = null;
function initMap() {
    if (map) return;
    map = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);
}
let vectorChart = null;
let currentChartType = 'bar'; // Default

function initVectorChart() {
    const ctx = document.getElementById('vectorChart').getContext('2d');
    
    const datasets = [
        {
            label: 'DNA (Auth)',
            data: scanHistory.map(s => s.dna_evidence?.auth_score || 0), //
            backgroundColor: '#ff4d4d',
            borderColor: '#ff4d4d',
            hidden: false
        },
        {
            label: 'Links (Typosquat)',
            data: scanHistory.map(s => s.link_evidence?.link_risk_score || 0), //
            backgroundColor: '#ffd60a',
            borderColor: '#ffd60a',
            hidden: false
        },
        {
            label: 'Profiling (Social Eng)',
            data: scanHistory.map(s => s.behavioral_evidence?.manipulation_score || 0), //
            backgroundColor: '#30d158',
            borderColor: '#30d158',
            hidden: false
        }
    ];

    vectorChart = new Chart(ctx, {
        type: currentChartType,
        data: {
            labels: scanHistory.map((_, i) => `Scan ${i+1}`),
            datasets: datasets
        },
        options: {
            responsive: true,
            scales: {
                x: { stacked: currentChartType === 'bar' },
                y: { 
                    stacked: currentChartType === 'bar',
                    beginAtZero: true,
                    max: currentChartType === 'bar' ? undefined : 100 
                }
            },
            plugins: {
                legend: { display: false } // We use custom toggles instead
            }
        }
    });

    if (!window.chartListenersSetup) {
        setupChartListeners();
        window.chartListenersSetup = true;
    }
}

function setupChartListeners() {
    // 1. Chart Type Switcher
    document.getElementById('toggleChartType').addEventListener('click', (e) => {
        currentChartType = currentChartType === 'bar' ? 'line' : 'bar';
        e.target.textContent = `Switch to ${currentChartType === 'bar' ? 'Line Graph' : 'Bar Chart'}`;
        
        vectorChart.destroy();
        initVectorChart();
    });

    // 2. Vector Toggles with "At Least One" Rule
    const checkboxes = document.querySelectorAll('.vector-toggle input');
    checkboxes.forEach((cb, index) => {
        cb.addEventListener('change', () => {
            const checkedCount = Array.from(checkboxes).filter(c => c.checked).length;
            
            if (checkedCount === 0) {
                cb.checked = true; // Force at least one selection
                alert("At least one forensic vector must remain active for analysis.");
                return;
            }

            // Toggle visibility in Chart.js
            vectorChart.setDatasetVisibility(index, cb.checked);
            vectorChart.update();
        });
    });
}