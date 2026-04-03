// ================= CHARTS =================

// LINE CHART
new Chart(document.getElementById('lineChart'), {
  type: 'line',
  data: {
    labels: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],
    datasets: [{
      label: 'Phishing Attempts',
      data: [3,7,5,12,8,2,4],
      borderColor: '#ff4d4d',
      backgroundColor: 'rgba(255,77,77,0.2)',
      fill: true,
      tension: 0.4
    }]
  }
});

// BAR CHART
new Chart(document.getElementById('barChart'), {
  type: 'bar',
  data: {
    labels: ['Credential Theft','Malware','BEC','Spear','Smishing'],
    datasets: [{
      data: [24,18,12,9,5],
      backgroundColor: '#2f80ed'
    }]
  },
  options: { indexAxis: 'y' }
});


// ================= MAP =================

const map = L.map('map').setView([20, 0], 2);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  attribution: '© OpenStreetMap'
}).addTo(map);


// 🔥 GLOBAL STORAGE (important for updates)
let markers = [];

// 🔥 FUNCTION TO UPDATE MAP (VERY IMPORTANT)
function updateMap(threatData) {

  // remove old markers
  markers.forEach(m => map.removeLayer(m));
  markers = [];

  // add new ones
  threatData.forEach(t => {
    const marker = L.circleMarker([t.lat, t.lng], {
      radius: t.count / 2 + 5,
      color: "#ff4d4d",
      fillColor: "#ff4d4d",
      fillOpacity: 0.6
    })
    .addTo(map)
    .bindPopup(`<b>${t.region}</b><br>${t.count} phishing attacks`);

    markers.push(marker);
  });
}


// ================= DEMO DATA =================

// You can replace this later with API
const sampleData = [
  { lat: 50, lng: 30, region: "Eastern Europe", count: 34 },
  { lat: 10, lng: 105, region: "Southeast Asia", count: 18 },
  { lat: 9, lng: -1, region: "West Africa", count: 22 },
  { lat: -15, lng: -60, region: "South America", count: 7 }
];

// initial load
updateMap(sampleData);


// ================= FUTURE READY =================

// 🔥 Example: later you can do this
/*
fetch("/api/threats")
  .then(res => res.json())
  .then(data => updateMap(data));
*/

// 🔥 OR from Gmail extension
/*
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "THREAT_DATA") {
    updateMap(msg.data);
  }
});
*/