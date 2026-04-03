const BACKEND = 'http://localhost:3000';
let accessToken = null;
let currentReport = null;

// Wait for the DOM to load before attaching events
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('signInBtn').addEventListener('click', signIn);
    document.getElementById('startScanBtn').addEventListener('click', startAnalysis);
    document.getElementById('backToDash').addEventListener('click', () => goTo('v-dash'));
    document.getElementById('backToList').addEventListener('click', () => goTo('v-list'));
    document.getElementById('fullBtn').addEventListener('click', openReport);
});

// ── Navigation ────────────────────────────────────────────────────────────────
function goTo(id) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(id).classList.add('active');
}

// ── Auth ──────────────────────────────────────────────────────────────────────
function signIn() {
    const errEl = document.getElementById('authErr');
    if (errEl) errEl.textContent = '';

    chrome.identity.getAuthToken({ interactive: true }, (token) => {
        if (chrome.runtime.lastError || !token) {
            if (errEl) errEl.textContent = 'Sign-in failed. Try again.';
            return;
        }
        accessToken = token;
        goTo('v-dash');
    });
}

// ── Fetch + Analyze ───────────────────────────────────────────────────────────
async function startAnalysis() {
    goTo('v-loading');

    const fill = document.getElementById('progFill');
    fill.style.transition = 'width 3s ease-out';
    setTimeout(() => fill.style.width = '90%', 50);

    let dots = 0;
    const dotTimer = setInterval(() => {
        dots = (dots + 1) % 4;
        document.getElementById('dnaText').textContent = 'AGENTIC SWARM ACTIVE' + '.'.repeat(dots);
    }, 350);

    try {
        const res = await fetch(`${BACKEND}/fetch-and-analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ accessToken, maxResults: 5 }),
        });

        const data = await res.json();
        clearInterval(dotTimer);
        fill.style.width = '100%';

        if (!data.success) throw new Error(data.error || 'Unknown error');

        setTimeout(() => {
            fill.style.transition = 'none';
            fill.style.width = '0';
            renderEmailList(data.results);
            goTo('v-list');
        }, 400);

    } catch (err) {
        clearInterval(dotTimer);
        fill.style.width = '0';
        document.getElementById('statusTxt').textContent = '✕ Error: ' + err.message;
        goTo('v-dash');
    }
}

// ── Email List ────────────────────────────────────────────────────────────────
function renderEmailList(results) {
    const list = document.getElementById('emailList');
    list.innerHTML = '';

    results.forEach(r => {
        // MAPPED TO NEW AI SCHEMA
        const score = r.final_risk_score || 0; 
        const threat = r.threat_level || 'Unknown';

        const color = score >= 70 ? '#ff2d55' : score >= 40 ? '#ffd60a' : '#30d158';
        const bg    = score >= 70 ? '#ff2d5511' : score >= 40 ? '#ffd60a11' : '#30d15811';
        const border= score >= 70 ? '#ff2d5533' : score >= 40 ? '#ffd60a33' : '#30d15833';

        const card = document.createElement('div');
        card.className = 'email-card';
        card.style.borderColor = border;
        card.innerHTML = `
            <div style="display:flex;align-items:center;gap:10px">
                <div class="email-score" style="color:${color}">${score}%</div>
                <div style="flex:1;min-width:0">
                    <div class="email-subject">${escHtml(r.subject)}</div>
                    <div class="email-sender">${escHtml(r.sender)}</div>
                </div>
                <div class="threat-pill" style="background:${bg};border:1px solid ${border};color:${color}">${escHtml(threat.toUpperCase())}</div>
            </div>`;
        
        card.addEventListener('click', () => showReport(r));
        list.appendChild(card);
    });
}

// ── Report ────────────────────────────────────────────────────────────────────
function showReport(r) {
    currentReport = r;

    const score = r.final_risk_score || 0;
    const threat = r.threat_level || 'Unknown';
    const evidence = r.key_evidence && r.key_evidence.length > 0 ? r.key_evidence : ['No specific indicators flagged.'];
    const summary = r.user_friendly_summary || 'Analysis complete.';

    const color = score >= 70 ? '#ff2d55' : score >= 40 ? '#ffd60a' : '#30d158';
    const bg    = score >= 70 ? '#ff2d5508' : score >= 40 ? '#ffd60a08' : '#30d15808';
    const border= score >= 70 ? '#ff2d5533' : score >= 40 ? '#ffd60a33' : '#30d15833';

    const badge = document.getElementById('riskBadge');
    badge.textContent = (score >= 70 ? '⚠ CRITICAL' : score >= 40 ? '▲ MODERATE' : '✓ SAFE') + ' THREAT';
    badge.style.background = bg;
    badge.style.border = `1px solid ${border}`;
    badge.style.color = color;

    // Findings list: include AI summary + key evidence
    const fl = document.getElementById('findingsList');
    const findings = [summary, ...evidence];
    fl.innerHTML = findings.map((f, i) =>
        `<div class="alert ${i === 0 ? 'red' : 'grey'}">${i === 0 ? '⚠' : '•'} ${escHtml(f)}</div>`
    ).join('');

    document.getElementById('rFrom').textContent = r.sender;
    document.getElementById('rFrom').style.color = score >= 70 ? '#ff2d55' : '#64748b';
    document.getElementById('rSubj').textContent = r.subject;

    if (r.is_fallback) {
       document.getElementById('rSubj').innerHTML += `<br><span style="font-size:10px; color:#ffd60a;">⚠️ Static Engine Fallback Active</span>`;
    }

    const fb = document.getElementById('fullBtn');
    fb.style.borderColor = border;
    fb.style.color = color;
    fb.style.background = bg;

    goTo('v-report');
    animateScore(score);
}

// ── Score Animation ───────────────────────────────────────────────────────────
function animateScore(target) {
    const scoreEl = document.getElementById('gaugeScore');
    const start = performance.now();

    (function step(now) {
        const p     = Math.min((now - start) / 1200, 1);
        const eased = 1 - Math.pow(1 - p, 3);
        const pct   = Math.round(eased * target);
        scoreEl.textContent = pct + '%';
        if (p < 1) requestAnimationFrame(step);
    })(start);
}

// ── Full Report ───────────────────────────────────────────────────────────────
function openReport() {
    if (!currentReport) return;
    chrome.storage.local.set({ lastReport: currentReport }, () => {
        chrome.tabs.create({ url: chrome.runtime.getURL('full_report.html') });
    });
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}