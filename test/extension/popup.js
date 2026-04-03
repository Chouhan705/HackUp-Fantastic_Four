const BACKEND = 'http://localhost:3000';
let accessToken = null;
let currentReport = null;

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('signInBtn').addEventListener('click', signIn);
    document.getElementById('startScanBtn').addEventListener('click', startAnalysis);
    document.getElementById('backToDash').addEventListener('click', () => goTo('v-dash'));
    document.getElementById('backToList').addEventListener('click', () => goTo('v-list'));
    document.getElementById('fullBtn').addEventListener('click', openReport);
});

/**
 * View Management
 */
function goTo(id) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(id).classList.add('active');
}

/**
 * Authentication via Google OAuth2
 */
function signIn() {
    const errEl = document.getElementById('authErr');
    if (errEl) errEl.textContent = '';
    
    chrome.identity.getAuthToken({ interactive: true }, (token) => {
        if (chrome.runtime.lastError || !token) {
            if (errEl) errEl.textContent = 'Sign-in failed. Try again.';
            console.error(chrome.runtime.lastError);
            return;
        }
        accessToken = token;
        goTo('v-dash');
    });
}

/**
 * Core Analysis Pipeline
 * Communicates with Node.js backend and logs results to storage
 */
async function startAnalysis() {
    goTo('v-loading');
    const fill = document.getElementById('progFill');
    fill.style.width = '0%';
    
    // UI Progress Bar Animation
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

        // LOGGING LOGIC: Save results to scanHistory for Dashboard widgets
        chrome.storage.local.get(['scanHistory'], (result) => {
            const history = result.scanHistory || [];
            // Append new forensic results to history array
            const updatedHistory = [...history, ...data.results]; 
            chrome.storage.local.set({ 
                scanHistory: updatedHistory,
                lastReport: data.results[0] // Set most recent for quick access
            });
        });

        setTimeout(() => {
            fill.style.width = '0';
            renderEmailList(data.results);
            goTo('v-list');
        }, 400);

    } catch (err) {
        clearInterval(dotTimer);
        document.getElementById('statusTxt').textContent = '✕ Error: ' + err.message;
        goTo('v-dash');
    }
}

/**
 * Renders the Inbox Scan list
 */
function renderEmailList(results) {
    const list = document.getElementById('emailList');
    list.innerHTML = '';
    
    results.forEach(r => {
        // Aligned with agents.js schema: final_risk_score
        const score = r.final_risk_score || 0;
        const color = score >= 70 ? '#ff2d55' : score >= 40 ? '#ffd60a' : '#30d158';
        const bg = score >= 70 ? '#ff2d5511' : score >= 40 ? '#ffd60a11' : '#30d15811';
        const border = score >= 70 ? '#ff2d5533' : score >= 40 ? '#ffd60a33' : '#30d15833';

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
                <div class="threat-pill" style="background:${bg};border:1px solid ${border};color:${color}">${r.threat_level || 'Safe'}</div>
            </div>`;
        card.addEventListener('click', () => showReport(r));
        list.appendChild(card);
    });
}

/**
 * Populates the detailed view for a selected email
 */
function showReport(r) {
    currentReport = r;
    const score = r.final_risk_score || 0;
    const color = score >= 70 ? '#ff2d55' : score >= 40 ? '#ffd60a' : '#30d158';
    const bg = score >= 70 ? '#ff2d5508' : score >= 40 ? '#ffd60a08' : '#30d15808';
    const border = score >= 70 ? '#ff2d5533' : score >= 40 ? '#ffd60a33' : '#30d15833';

    // Update SVG Gauge colors
    document.getElementById('g1').setAttribute('stop-color', color);
    document.getElementById('g2').setAttribute('stop-color', color);
    document.getElementById('gaugeScore').setAttribute('fill', color);
    document.getElementById('gaugeDot').setAttribute('fill', color);

    const badge = document.getElementById('riskBadge');
    badge.textContent = (score >= 70 ? '⚠ CRITICAL' : score >= 40 ? '▲ MODERATE' : '✓ SAFE') + ' THREAT';
    badge.style.cssText = `background:${bg};border:1px solid ${border};color:${color};`;

    document.getElementById('alertCard').style.cssText = `background:${bg};border:1px solid ${border}`;
    document.getElementById('alertHead').style.color = color;
    document.getElementById('alertHead').textContent = r.user_friendly_summary || "Analysis complete";

    const fl = document.getElementById('findingsList');
    const evidence = r.key_evidence || []; // Aligned with Agent Judge output
    fl.innerHTML = evidence.map(f =>
        `<div class="finding-item"><div class="finding-dot" style="background:${color}"></div>${escHtml(f)}</div>`
    ).join('');

    document.getElementById('rFrom').textContent = r.sender;
    document.getElementById('rSubj').textContent = r.subject;
    
    if (r.is_fallback) {
        document.getElementById('rSubj').innerHTML += ` <span style="color:#ffd60a;">[OFFLINE SCAN]</span>`;
    }

    const fb = document.getElementById('fullBtn');
    fb.style.cssText = `border:1px solid ${border};color:${color}`;

    goTo('v-report');
    animateGauge(score, color);
}

/**
 * Animated SVG Gauge logic
 */
function animateGauge(target, color) {
    const scoreEl = document.getElementById('gaugeScore');
    const arcEl = document.getElementById('gaugeArc');
    const dotEl = document.getElementById('gaugeDot');
    const cx = 100, cy = 95, R = 72;

    function polarXY(angle) {
        return { x: cx + R * Math.cos(angle), y: cy - R * Math.sin(angle) };
    }

    const start = performance.now();
    (function step(now) {
        const p = Math.min((now - start) / 1200, 1);
        const eased = 1 - Math.pow(1 - p, 3);
        const pct = eased * target;

        scoreEl.textContent = Math.round(pct) + '%';

        const angle = Math.PI - (pct / 100) * Math.PI;
        const tip = polarXY(angle);
        const bigArc = pct > 50 ? 1 : 0;
        const s = polarXY(Math.PI);
        arcEl.setAttribute('d', `M ${s.x} ${s.y} A ${R} ${R} 0 ${bigArc} 1 ${tip.x} ${tip.y}`);
        dotEl.setAttribute('cx', tip.x);
        dotEl.setAttribute('cy', tip.y);

        if (p < 1) requestAnimationFrame(step);
    })(start);
}

/**
 * Opens the Full Forensic Report in a new tab
 */
function openReport() {
    if (!currentReport) return;
    chrome.storage.local.set({ lastReport: currentReport }, () => {
        chrome.tabs.create({ url: chrome.runtime.getURL('report.html') });
    });
}

/**
 * Basic XSS protection for HTML rendering
 */
function escHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}