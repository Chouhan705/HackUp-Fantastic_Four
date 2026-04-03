// ================= NAVIGATION =================
 
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
 
    // Active nav item
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
 
    // Show correct section
    const sectionId = 'section-' + item.dataset.section;
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
 
    // Update page title
    document.getElementById('pageTitle').textContent =
      item.textContent.trim();
 
    // Init lazy charts/map on first visit
    if (item.dataset.section === 'analytics' && !window._analyticsInit) {
      window._analyticsInit = true;
      initAnalyticsCharts();
    }
    if (item.dataset.section === 'geo' && !window._mapInit) {
      window._mapInit = true;
      initMap();
    }
  });
});
 
 
// ================= CHART.JS DEFAULTS =================
 
Chart.defaults.color = '#4a5a7a';
Chart.defaults.borderColor = '#1a2540';
Chart.defaults.font.family = "'Share Tech Mono', monospace";
Chart.defaults.font.size = 11;
 
 
// ================= OVERVIEW CHARTS =================
 
// LINE CHART — Overview
new Chart(document.getElementById('lineChart'), {
  type: 'line',
  data: {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    datasets: [{
      label: 'Phishing Attempts',
      data: [3, 7, 5, 12, 8, 2, 4],
      borderColor: '#ff4d4d',
      backgroundColor: 'rgba(255,77,77,0.12)',
      fill: true,
      tension: 0.4,
      pointBackgroundColor: '#ff4d4d',
      pointRadius: 4,
      pointHoverRadius: 6,
      borderWidth: 2
    }]
  },
  options: {
    responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: '#1a2540' } },
      y: { grid: { color: '#1a2540' }, beginAtZero: true }
    }
  }
});
 
// BAR CHART — Overview
new Chart(document.getElementById('barChart'), {
  type: 'bar',
  data: {
    labels: ['Credential Theft', 'Malware', 'BEC', 'Spear', 'Smishing'],
    datasets: [{
      data: [24, 18, 12, 9, 5],
      backgroundColor: [
        'rgba(255,77,77,.7)',
        'rgba(255,77,77,.5)',
        'rgba(255,214,10,.6)',
        'rgba(255,214,10,.4)',
        'rgba(48,209,88,.4)'
      ],
      borderRadius: 4,
      borderSkipped: false
    }]
  },
  options: {
    indexAxis: 'y',
    responsive: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: '#1a2540' }, beginAtZero: true },
      y: { grid: { display: false } }
    }
  }
});
 
 
// ================= ANALYTICS CHARTS =================
 
function initAnalyticsCharts() {
 
  // LINE CHART 2 — Analytics
  new Chart(document.getElementById('lineChart2'), {
    type: 'line',
    data: {
      labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
      datasets: [
        {
          label: 'Phishing',
          data: [3, 7, 5, 12, 8, 2, 4],
          borderColor: '#ff4d4d',
          backgroundColor: 'rgba(255,77,77,.08)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          borderWidth: 2
        },
        {
          label: 'Suspicious',
          data: [5, 9, 6, 8, 11, 4, 7],
          borderColor: '#ffd60a',
          backgroundColor: 'rgba(255,214,10,.06)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          borderWidth: 2
        }
      ]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          display: true,
          labels: { boxWidth: 10, padding: 16, color: '#4a5a7a' }
        }
      },
      scales: {
        x: { grid: { color: '#1a2540' } },
        y: { grid: { color: '#1a2540' }, beginAtZero: true }
      }
    }
  });
 
  // DOUGHNUT CHART
  new Chart(document.getElementById('doughnutChart'), {
    type: 'doughnut',
    data: {
      labels: ['Phishing', 'Suspicious', 'Safe'],
      datasets: [{
        data: [47, 39, 1198],
        backgroundColor: [
          'rgba(255,77,77,.8)',
          'rgba(255,214,10,.7)',
          'rgba(48,209,88,.6)'
        ],
        borderColor: '#0d1526',
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          display: true,
          position: 'bottom',
          labels: { boxWidth: 10, padding: 14, color: '#4a5a7a' }
        }
      },
      cutout: '65%'
    }
  });
 
  // BAR CHART 2 — Analytics
  new Chart(document.getElementById('barChart2'), {
    type: 'bar',
    data: {
      labels: ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],
      datasets: [{
        label: 'Attacks',
        data: [14, 22, 18, 31, 27, 42, 38, 47, 33, 29, 51, 44],
        backgroundColor: 'rgba(255,77,77,.55)',
        borderRadius: 4,
        borderSkipped: false
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { grid: { color: '#1a2540' }, beginAtZero: true }
      }
    }
  });
}
 
 
// ================= MAP =================
 
let map = null;
let markers = [];
 
function initMap() {
  if (map) return;
 
  map = L.map('map').setView([20, 0], 2);
 
  // Dark-themed tiles
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '© OpenStreetMap © CARTO',
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(map);
 
  updateMap(sampleData);
}
 
// 🔥 GLOBAL STORAGE (important for updates)
function updateMap(threatData) {
  if (!map) return;
 
  // remove old markers
  markers.forEach(m => map.removeLayer(m));
  markers = [];
 
  threatData.forEach(t => {
    const marker = L.circleMarker([t.lat, t.lng], {
      radius: t.count / 2 + 5,
      color: '#ff4d4d',
      fillColor: '#ff4d4d',
      fillOpacity: 0.55,
      weight: 1.5
    })
    .addTo(map)
    .bindPopup(`<b style="font-family:monospace">${t.region}</b><br/>${t.count} phishing attacks`);
 
    markers.push(marker);
  });
}
 
 
// ================= DEMO DATA =================
 
const sampleData = [
  { lat: 50, lng: 30,   region: 'Eastern Europe',  count: 34 },
  { lat: 10, lng: 105,  region: 'Southeast Asia',  count: 18 },
  { lat:  9, lng: -1,   region: 'West Africa',     count: 22 },
  { lat:-15, lng: -60,  region: 'South America',   count:  7 }
];
 
 
// ================= FUTURE READY =================
 
/*
fetch("/api/threats")
  .then(res => res.json())
  .then(data => updateMap(data));
*/
 
/*
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "THREAT_DATA") {
    updateMap(msg.data);
  }
});
*/
 