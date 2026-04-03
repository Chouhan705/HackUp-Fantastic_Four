// ── Load report data from chrome.storage ─────────────────────────────────────

function loadReport(r) {
  if (!r) {
    // Fallback demo data if opened directly (not from extension)
    r = {
      score: 89,
      sender: 'noreply@paypa1-secure.xyz',
      subject: 'Action Required: Verify your PayPal account immediately',
      threatLevel: 'CRITICAL',
      findings: [
        '⚠ "Your account will be suspended" — urgency language detected',
        '⚠ "Click here immediately" — call-to-action pressure pattern',
        '⚠ "Verify your bank details" — credential harvesting attempt',
        '⚠ Sender domain does not match PayPal official domains'
      ]
    };
  }

  // Color scheme
  const color  = r.score >= 70 ? '#ff4d4d' : r.score >= 40 ? '#ffd60a' : '#30d158';
  const bg     = r.score >= 70 ? 'rgba(255,77,77,.1)'   : r.score >= 40 ? 'rgba(255,214,10,.1)'  : 'rgba(48,209,88,.1)';
  const border = r.score >= 70 ? 'rgba(255,77,77,.25)'  : r.score >= 40 ? 'rgba(255,214,10,.25)' : 'rgba(48,209,88,.25)';

  // Top badge
  const badge = document.getElementById('riskBadgeFull');
  badge.textContent = r.score >= 70 ? '⚠ CRITICAL THREAT' : r.score >= 40 ? '▲ MODERATE THREAT' : '✓ SAFE';
  badge.style.background = bg;
  badge.style.borderColor = border;
  badge.style.color = color;

  // Score arc animation
  const arcEl   = document.getElementById('scoreArc');
  const scoreEl = document.getElementById('scoreNum');
  const circumference = 2 * Math.PI * 54; // 339.3

  arcEl.style.stroke = color;
  scoreEl.style.color = color;

  const start = performance.now();
  (function step(now) {
    const p     = Math.min((now - start) / 1200, 1);
    const eased = 1 - Math.pow(1 - p, 3);
    const pct   = eased * r.score;

    scoreEl.textContent = Math.round(pct) + '%';
    arcEl.style.strokeDashoffset = circumference - (pct / 100) * circumference;

    if (p < 1) requestAnimationFrame(step);
  })(start);

  // Meta strip
  document.getElementById('metaConf').textContent =
    r.score >= 70 ? '97.2%' : r.score >= 40 ? '68.5%' : '99.1%';
  document.getElementById('metaType').textContent = r.threatLevel || 'Unknown';

  // From / Subject
  document.getElementById('rFrom').textContent = r.sender  || '—';
  document.getElementById('rSubj').textContent = r.subject || '—';

  // Findings
  const fl = document.getElementById('findingsList');
  fl.innerHTML = '';
  (r.findings || []).forEach((f, i) => {
    const div = document.createElement('div');
    div.className = 'finding-card ' + (i === 0 ? 'red' : 'grey');
    div.textContent = f;
    fl.appendChild(div);
  });
}

// ── Entry point ───────────────────────────────────────────────────────────────

if (typeof chrome !== 'undefined' && chrome.storage) {
  chrome.storage.local.get(['lastReport'], (result) => {
    loadReport(result.lastReport || null);
  });
} else {
  // Running in a regular browser tab (dev/preview mode)
  loadReport(null);
}