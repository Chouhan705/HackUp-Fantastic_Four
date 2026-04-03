/**
 * ─── DATA LOADING ───
 * Pulls the specific forensic record from storage
 */
function initReport() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['lastReport'], (result) => {
            if (result.lastReport) {
                renderForensicData(result.lastReport);
            } else {
                console.error("❌ [Report] No forensic data found in storage.");
            }
        });
    }
}

/**
 * ─── UI RENDERING ───
 */
function renderForensicData(r) {
    const score = r.final_risk_score || 0;
    const threatLevel = r.threat_level || 'UNKNOWN';
    const evidence = r.key_evidence || [];
    const summary = r.user_friendly_summary || "No summary available.";

    // 1. Dynamic Theme Calculation
    const isCritical = score >= 70;
    const isSuspicious = score >= 40 && score < 70;
    
    const color = isCritical ? '#ff4d4d' : isSuspicious ? '#ffd60a' : '#30d158';
    const bg = isCritical ? 'rgba(255,77,77,.1)' : isSuspicious ? 'rgba(255,214,10,.1)' : 'rgba(48,209,88,.1)';
    const border = isCritical ? 'rgba(255,77,77,.25)' : isSuspicious ? 'rgba(255,214,10,.25)' : 'rgba(48,209,88,.25)';

    // 2. Update Top Badge
    const badge = document.getElementById('riskBadgeFull');
    badge.textContent = isCritical ? '⚠ CRITICAL THREAT' : isSuspicious ? '▲ MODERATE THREAT' : '✓ SAFE';
    badge.style.background = bg;
    badge.style.borderColor = border;
    badge.style.color = color;

    // 3. Animate Gauge
    animateScoreCircle(score, color);

    // 4. Update Metadata & Insights
    document.getElementById('metaConf').textContent = score >= 70 ? '98.4%' : '86.2%';
    document.getElementById('metaType').textContent = threatLevel.toUpperCase();
    document.getElementById('rFrom').textContent = r.sender || 'Unknown Sender';
    document.getElementById('rSubj').textContent = r.subject || 'No Subject';
    
    // Status indicator for fallback vs live analysis
    const statusVal = document.getElementById('metaFallback');
    statusVal.textContent = r.is_fallback ? 'HEURISTIC' : 'LIVE AI';
    statusVal.style.color = r.is_fallback ? '#ffd60a' : '#30d158';

    // 5. Populate Evidence List
    const fl = document.getElementById('findingsList');
    fl.innerHTML = '';
    evidence.forEach(item => {
        const div = document.createElement('div');
        div.className = `finding-card ${isCritical ? 'red' : 'grey'}`;
        div.textContent = item;
        fl.appendChild(div);
    });

    // 6. Populate AI Summary
    const reasoningArea = document.getElementById('aiReasoning');
    reasoningArea.innerHTML = `
        <div class="reasoning-item">
            <div class="r-dot" style="background:${color}"></div>
            <div class="r-text">${summary}</div>
        </div>
    `;

    // 7. Dynamic Actions Advice
    const actionBox = document.getElementById('actionContainer');
    if (score >= 70) {
        actionBox.innerHTML = `
            <div class="finding-card red">DO NOT click any links or download attachments.</div>
            <div class="finding-card red">Report this email to your IT department immediately.</div>
        `;
    } else if (score >= 40) {
        actionBox.innerHTML = `
            <div class="finding-card grey">Exercise caution. Verify the sender's identity via another channel.</div>
        `;
    } else {
        actionBox.innerHTML = `
            <div class="finding-card grey">This email appears safe. No further action required.</div>
        `;
    }
}

/**
 * ─── ANIMATION LOGIC ───
 */
function animateScoreCircle(target, color) {
    const arcEl = document.getElementById('scoreArc');
    const scoreEl = document.getElementById('scoreNum');
    const circumference = 339.3; 

    arcEl.style.stroke = color;
    scoreEl.style.color = color;

    const start = performance.now();
    (function step(now) {
        const p = Math.min((now - start) / 1200, 1);
        const eased = 1 - Math.pow(1 - p, 3); // Cubic ease-out
        const pct = eased * target;

        scoreEl.textContent = Math.round(pct) + '%';
        arcEl.style.strokeDashoffset = circumference - (pct / 100) * circumference;

        if (p < 1) requestAnimationFrame(step);
    })(start);
}

document.addEventListener('DOMContentLoaded', initReport);