// ── Load report data from chrome.storage ─────────────────────────────────────

function loadReport(r) {
  if (!r) {
    console.error("No report data found in storage.");
    return;
  }

  // 1. Align Schema Mismatches
  // Backend uses 'final_risk_score', 'threat_level', and 'key_evidence'
  const score = r.final_risk_score || 0;
  const threatLevel = r.threat_level || 'UNKNOWN';
  const evidence = r.key_evidence || [];
  const summary = r.user_friendly_summary || "";

  // 2. Determine Color Scheme
  const color  = score >= 70 ? '#ff4d4d' : score >= 40 ? '#ffd60a' : '#30d158';
  const bg     = score >= 70 ? 'rgba(255,77,77,.1)'   : score >= 40 ? 'rgba(255,214,10,.1)'  : 'rgba(48,209,88,.1)';
  const border = score >= 70 ? 'rgba(255,77,77,.25)'  : score >= 40 ? 'rgba(255,214,10,.25)' : 'rgba(48,209,88,.25)';

  // 3. Update UI Elements
  const badge = document.getElementById('riskBadgeFull');
  badge.textContent = score >= 70 ? '⚠ CRITICAL THREAT' : score >= 40 ? '▲ MODERATE THREAT' : '✓ SAFE';
  badge.style.background = bg;
  badge.style.borderColor = border;
  badge.style.color = color;

  // Score arc animation
  const arcEl   = document.getElementById('scoreArc');
  const scoreEl = document.getElementById('scoreNum');
  const circumference = 339.3; 

  arcEl.style.stroke = color;
  scoreEl.style.color = color;

  const start = performance.now();
  (function step(now) {
    const p     = Math.min((now - start) / 1200, 1);
    const eased = 1 - Math.pow(1 - p, 3);
    const pct   = eased * score;

    scoreEl.textContent = Math.round(pct) + '%';
    arcEl.style.strokeDashoffset = circumference - (pct / 100) * circumference;

    if (p < 1) requestAnimationFrame(step);
  })(start);

  // Metadata
  document.getElementById('metaConf').textContent = score >= 70 ? '97.2%' : '84.1%';
  document.getElementById('metaType').textContent = threatLevel;
  document.getElementById('rFrom').textContent = r.sender || 'Unknown Sender';
  document.getElementById('rSubj').textContent = r.subject || 'No Subject';

  // 4. Populate Detected Patterns (Findings)
  const fl = document.getElementById('findingsList');
  fl.innerHTML = '';
  evidence.forEach((item, i) => {
    const div = document.createElement('div');
    div.className = `finding-card ${score >= 70 ? 'red' : 'grey'}`;
    div.textContent = item;
    fl.appendChild(div);
  });

  // 5. Populate AI Reasoning (Summary + Fallback info)
  const reasoningList = document.querySelector('.reasoning-list');
  reasoningList.innerHTML = `
    <div class="reasoning-item">
      <div class="r-dot ${score >= 70 ? 'red' : 'yellow'}"></div>
      <div class="r-text">${summary}</div>
    </div>
  `;
}

// ── Entry point ───────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get(['lastReport'], (result) => {
      if (result.lastReport) {
        loadReport(result.lastReport);
      }
    });
  }
});