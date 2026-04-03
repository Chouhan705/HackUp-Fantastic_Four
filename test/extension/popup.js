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
        document.getElementById('dnaText').textContent = 'ANALYZING DNA' + '.'.repeat(dots);
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
        const color  = r.score >= 70 ? '#ff4d4d' : r.score >= 40 ? '#ffd60a' : '#30d158';
        const bg     = r.score >= 70 ? 'rgba(255,77,77,.12)'  : r.score >= 40 ? 'rgba(255,214,10,.12)'  : 'rgba(48,209,88,.12)';
        const border = r.score >= 70 ? 'rgba(255,77,77,.3)'   : r.score >= 40 ? 'rgba(255,214,10,.3)'   : 'rgba(48,209,88,.3)';

        const card = document.createElement('div');
        card.className = 'email-card';
        card.style.borderColor = border;
        card.innerHTML = `
            <div class="email-score" style="color:${color}">${r.score}%</div>
            <div style="flex:1;min-width:0">
                <div class="email-subject">${escHtml(r.subject)}</div>
                <div class="email-sender">${escHtml(r.sender)}</div>
            </div>
            <div class="threat-pill" style="background:${bg};border:1px solid ${border};color:${color}">${escHtml(r.threatLevel)}</div>`;

        card.addEventListener('click', () => showReport(r));
        list.appendChild(card);
    });
}

// ── Report ────────────────────────────────────────────────────────────────────
function showReport(r) {
    currentReport = r;

    // Color scheme based on score
    const color  = r.score >= 70 ? '#ff4d4d' : r.score >= 40 ? '#ffd60a' : '#30d158';
    const bg     = r.score >= 70 ? 'rgba(255,77,77,.12)'  : r.score >= 40 ? 'rgba(255,214,10,.12)'  : 'rgba(48,209,88,.12)';
    const border = r.score >= 70 ? 'rgba(255,77,77,.3)'   : r.score >= 40 ? 'rgba(255,214,10,.3)'   : 'rgba(48,209,88,.3)';

    // Risk badge in header
    const badge = document.getElementById('riskBadge');
    badge.textContent = r.score >= 70 ? 'Phishing' : r.score >= 40 ? 'Suspicious' : 'Safe';
    badge.style.background = bg;
    badge.style.border = `1px solid ${border}`;
    badge.style.color = color;

    // Big percentage circle
    const scoreEl = document.getElementById('gaugeScore');
    scoreEl.style.color = color;
    scoreEl.style.textShadow = `0 0 30px ${color}80`;

    // Findings → alert cards
    const fl = document.getElementById('findingsList');
    fl.innerHTML = '';
    r.findings.forEach((f, i) => {
        const div = document.createElement('div');
        // First finding (most severe) = red, rest = grey
        div.className = 'alert ' + (i === 0 ? 'red' : 'grey');
        div.textContent = '⚠ ' + f;
        fl.appendChild(div);
    });

    // Meta rows
    document.getElementById('rFrom').textContent = r.sender;
    document.getElementById('rFrom').style.color  = r.score >= 70 ? '#ff4d4d' : '#5a6a8a';
    document.getElementById('rSubj').textContent = r.subject;

    // Full report button color
    const fb = document.getElementById('fullBtn');
    fb.style.borderColor = border;
    fb.style.color = color;
    fb.style.background = bg;

    goTo('v-report');
    animateScore(r.score, color);
}

// ── Score Animation (replaces gauge) ─────────────────────────────────────────
function animateScore(target, color) {
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