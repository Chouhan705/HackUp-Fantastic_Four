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
function updateStats() {
    const total = scanHistory.length;
    const phish = scanHistory.filter(s => s.final_risk_score >= 70).length;
    const safe = scanHistory.filter(s => s.final_risk_score < 40).length;
    const rate = total > 0 ? ((safe / total) * 100).toFixed(1) : 100;

    document.getElementById('statTotal').textContent = total;
    document.getElementById('statPhish').textContent = phish;
    document.getElementById('statSafe').textContent = safe;
    document.getElementById('statRate').textContent = rate + '%';

    const badge = document.getElementById('globalThreatBadge');
    if (phish > 0) {
        badge.className = 'threat-level-badge danger';
        document.getElementById('globalThreatText').textContent = 'ELEVATED THREAT';
    }
}

function updateActivityTable() {
    const tbody = document.getElementById('activityTableBody');
    tbody.innerHTML = '';
    scanHistory.slice(-10).reverse().forEach(entry => {
        const score = entry.final_risk_score || 0;
        const status = score >= 70 ? 'red' : score >= 40 ? 'yellow' : 'green';
        const row = `
            <tr>
                <td>${entry.date || 'Today'}</td>
                <td>${entry.subject}</td>
                <td>${entry.sender.split('<')[0]}</td>
                <td class="${status}">${score}%</td>
                <td><span class="pill ${status}">${status.toUpperCase()}</span></td>
            </tr>
        `;
        tbody.insertAdjacentHTML('beforeend', row);
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
}

let map = null;
function initMap() {
    if (map) return;
    map = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png').addTo(map);
}