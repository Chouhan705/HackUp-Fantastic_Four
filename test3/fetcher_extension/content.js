// content/content.js
// Watches Gmail for email open events, injects sidebar, drives scan flow.

(function () {
  "use strict";

  // ─── State ────────────────────────────────────────────────────────────────

  let currentMessageId = null;
  let sidebar          = null;
  let observer         = null;

  // ─── Gmail Message ID extraction ─────────────────────────────────────────

  /**
   * Gmail URLs look like:
   *   https://mail.google.com/mail/u/0/#inbox/FMfcgzGxRBtKjvQgZvLpHwnpJxCVDpSk
   *   https://mail.google.com/mail/u/0/#search/label/18c2e5f7f8a9b0c1
   * The hash fragment's last segment is the message/thread ID.
   */
  function extractMessageId() {
    const hash = window.location.hash;
    const parts = hash.replace("#", "").split("/");
    const id = parts[parts.length - 1];
    // Gmail message IDs are hex strings, 16+ chars
    return id && /^[0-9a-fA-F]{10,}$/.test(id) ? id : null;
  }

  // ─── Sidebar ──────────────────────────────────────────────────────────────

  function createSidebar() {
    // Use Shadow DOM so Gmail CSS doesn't bleed in
    const host = document.createElement("div");
    host.id    = "nophishzone-host";
    host.style.cssText = `
      position: fixed;
      top: 120px;
      right: 0;
      width: 300px;
      z-index: 9999;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    `;

    const shadow = host.attachShadow({ mode: "open" });

    shadow.innerHTML = `
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }

        #panel {
          background: #1e1e2e;
          backdrop-filter: blur(8px);
          -webkit-backdrop-filter: blur(8px);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-right: none;
          border-radius: 14px 0 0 14px;
          box-shadow: -8px 8px 32px rgba(0, 0, 0, 0.3), inset 0 0 0 1px rgba(255, 255, 255, 0.05);
          overflow: hidden;
          transition: width 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
          color: #e0e0e0;
        }

        #header {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 14px 16px;
          background: linear-gradient(135deg, #4a00e0 0%, #8e2de2 100%);
          color: #ffffff;
          border-bottom: 1px solid rgba(255, 255, 255, 0.1);
          cursor: pointer;
          user-select: none;
        }
        #header-icon { font-size: 20px; text-shadow: 0 2px 4px rgba(0,0,0,0.2); }
        #header-title { font-size: 14px; font-weight: 600; color: #ffffff; flex: 1; letter-spacing: 0.3px; }
        #collapse-btn { font-size: 20px; color: rgba(255, 255, 255, 0.8); line-height: 1; transition: color 0.2s; }
        #header:hover #collapse-btn { color: #fff; }

        #body { padding: 16px; }

        /* States */
        #state-idle, #state-scanning, #state-result, #state-error { display: none; }
        #state-idle.active, #state-scanning.active,
        #state-result.active, #state-error.active { display: block; animation: fadeIn 0.4s ease; }

        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(4px); }
          to { opacity: 1; transform: translateY(0); }
        }

        #scan-btn {
          width: 100%;
          padding: 10px 0;
          background: linear-gradient(135deg, #1a73e8 0%, #1558c0 100%);
          color: #fff;
          border: none;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          box-shadow: 0 4px 12px rgba(26, 115, 232, 0.3);
          transition: all 0.2s ease;
        }
        #scan-btn:hover { background: linear-gradient(135deg, #1558c0 0%, #0d3b82 100%); transform: translateY(-1px) scale(1.02); box-shadow: 0 6px 16px rgba(26, 115, 232, 0.4); }
        #scan-btn:active { transform: translateY(1px) scale(0.98); }

        .scanning-text {
          font-size: 14px;
          font-weight: 500;
          color: #444;
          text-align: center;
          padding: 12px 0;
        }
        .dots::after {
          content: '';
          animation: dots 1.4s infinite;
        }
        @keyframes dots {
          0%   { content: '.'; }
          33%  { content: '..'; }
          66%  { content: '...'; }
        }

        /* Verdict */
        .verdict-badge {
          display: inline-block;
          padding: 6px 14px;
          border-radius: 100px;
          font-size: 13px;
          font-weight: 700;
          margin-bottom: 16px;
          letter-spacing: 0.5px;
          text-transform: uppercase;
        }
        .verdict-safe      { background: #eaf3de; color: #3b6d11; border: 1px solid #d4ebbc; box-shadow: 0 0 12px rgba(99, 153, 34, 0.2); }
        .verdict-suspicious{ background: #faeeda; color: #854f0b; border: 1px solid #f2d6a2; box-shadow: 0 0 16px rgba(239, 159, 39, 0.4); animation: glow-suspicious 2s infinite alternate; }
        .verdict-phishing  { background: #fcebeb; color: #a32d2d; border: 1px solid #f3c2c2; box-shadow: 0 0 16px rgba(226, 75, 74, 0.4); animation: glow-phishing 2s infinite alternate; }

        @keyframes glow-phishing {
          from { box-shadow: 0 0 10px rgba(226, 75, 74, 0.3); }
          to { box-shadow: 0 0 20px rgba(226, 75, 74, 0.7); }
        }
        @keyframes glow-suspicious {
          from { box-shadow: 0 0 10px rgba(239, 159, 39, 0.3); }
          to { box-shadow: 0 0 20px rgba(239, 159, 39, 0.7); }
        }

        .score-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
        }
        .score-label { font-size: 13px; font-weight: 600; color: #555; }
        .score-val   { font-size: 26px; font-weight: 800; color: #111; letter-spacing: -0.5px; }

        .score-bar-track {
          height: 8px;
          background: rgba(0, 0, 0, 0.05);
          border-radius: 4px;
          margin-bottom: 20px;
          overflow: hidden;
          box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
        }
        .score-bar-fill {
          height: 100%;
          border-radius: 4px;
          transition: width 0.8s cubic-bezier(0.25, 0.8, 0.25, 1);
          animation: bar-pulse 2s infinite;
        }

        @keyframes bar-pulse {
          0% { filter: brightness(1); }
          50% { filter: brightness(1.15); }
          100% { filter: brightness(1); }
        }

        .signals-title { font-size: 12px; font-weight: 700; color: #777; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 10px; }
        
        .signal-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 10px 12px;
          background: rgba(255, 255, 255, 0.9);
          border: 1px solid rgba(0, 0, 0, 0.06);
          border-radius: 10px;
          margin-bottom: 8px;
          box-shadow: 0 2px 6px rgba(0,0,0,0.02);
          transition: transform 0.2s, box-shadow 0.2s;
        }
        .signal-item:hover {
          transform: translateY(-1px);
          box-shadow: 0 4px 10px rgba(0,0,0,0.05);
        }
        
        .signal-engine { font-size: 13px; font-weight: 600; color: #222; }
        .signal-score  { font-size: 12px; font-weight: 700; padding: 3px 8px; border-radius: 100px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .signal-flags  { font-size: 11px; color: #777; margin-top: 3px; font-weight: 500; }

        .sig-high { background: rgba(226, 75, 74, 0.2); color: #ff6b6b; border: 1px solid rgba(255, 107, 107, 0.3); }
        .sig-mid  { background: rgba(239, 159, 39, 0.2); color: #fbc658; border: 1px solid rgba(251, 198, 88, 0.3); }
        .sig-low  { background: rgba(99, 153, 34, 0.2); color: #8fd14f; border: 1px solid rgba(143, 209, 79, 0.3); }

        .cached-note { font-size: 11px; font-weight: 500; color: #777; text-align: right; margin-top: 14px; }

        .error-text { font-size: 13px; font-weight: 500; color: #ff6b6b; line-height: 1.5; background: rgba(226, 75, 74, 0.2); padding: 10px; border-radius: 8px; border: 1px solid rgba(255, 107, 107, 0.3); }
        .retry-btn {
          margin-top: 12px;
          width: 100%;
          font-size: 13px;
          font-weight: 600;
          padding: 9px 14px;
          border: 1px solid #ff6b6b;
          background: transparent;
          color: #ff6b6b;
          border-radius: 8px;
          cursor: pointer;
          transition: all 0.2s ease;
          box-shadow: 0 2px 6px rgba(226, 75, 74, 0.1);
        }
        .retry-btn:hover {
          background: rgba(226, 75, 74, 0.1);
          transform: translateY(-1px) scale(1.02);
          box-shadow: 0 4px 10px rgba(226, 75, 74, 0.3);
        }
        .retry-btn:active { transform: translateY(1px) scale(0.98); }
      </style>

      <div id="panel">
        <div id="header">
          <span id="header-icon">🛡️</span>
          <span id="header-title">NoPhishZone</span>
          <span id="collapse-btn">−</span>
        </div>
        <div id="body">
          <!-- IDLE: waiting for user to trigger scan -->
          <div id="state-idle" class="active">
            <p style="font-size:13px;color:#aaa;margin-bottom:14px;line-height:1.5;font-weight:500;">
              Click below to scan this email for phishing signals.
            </p>
            <button id="scan-btn">Scan this email</button>
          </div>

          <!-- SCANNING -->
          <div id="state-scanning">
            <p class="scanning-text">Scanning<span class="dots"></span></p>
          </div>

          <!-- RESULT -->
          <div id="state-result">
            <span id="verdict-badge" class="verdict-badge"></span>
            <div class="score-row">
              <span class="score-label">Risk score</span>
              <span id="score-val" class="score-val"></span>
            </div>
            <div class="score-bar-track">
              <div id="score-bar" class="score-bar-fill"></div>
            </div>
            <div class="signals-title">Engine signals</div>
            <div id="signals-list"></div>
            <p id="cached-note" class="cached-note"></p>
          </div>

          <!-- ERROR -->
          <div id="state-error">
            <p class="error-text" id="error-msg"></p>
            <button class="retry-btn" id="retry-btn">Retry</button>
          </div>
        </div>
      </div>
    `;

    return { host, shadow };
  }

  function setState(shadow, name) {
    shadow.querySelectorAll("#state-idle, #state-scanning, #state-result, #state-error")
      .forEach((el) => el.classList.remove("active"));
    shadow.getElementById(`state-${name}`).classList.add("active");
  }

  function renderResult(shadow, result) {
    const { score, verdict, signals, cached, malicious_urls, explanation } = result;

    // Badge
    const badge = shadow.getElementById("verdict-badge");
    badge.textContent = verdict.charAt(0).toUpperCase() + verdict.slice(1);
    badge.className   = `verdict-badge verdict-${verdict}`;

    // Score
    shadow.getElementById("score-val").textContent = score;

    // Bar color
    const bar   = shadow.getElementById("score-bar");
    const color = score >= 70 ? "#e24b4a" : score >= 40 ? "#ef9f27" : "#639922";
    bar.style.width      = `${score}%`;
    bar.style.background = color;

    // Additional info rendering (URLs and explanations)
    let urlHtml = "";
    if (malicious_urls && malicious_urls.length > 0) {
      urlHtml = `
        <div class="signals-title" style="margin-top: 14px;">Malicious URLs Found</div>
        <div style="font-size: 11px; padding: 7px 10px; background: #fcebeb; border-radius: 7px; color: #a32d2d; margin-bottom: 10px; word-wrap: break-word;">
          ${malicious_urls.map(u => `<div>🔗 ${u}</div>`).join("")}
        </div>
      `;
    }

    let expHtml = "";
    if (explanation) {
      expHtml = `
        <div class="signals-title" style="margin-top: 10px;">Analyzer Findings</div>
        <div style="font-size: 11px; padding: 7px 10px; background: #faeeda; border-radius: 7px; color: #854f0b; margin-bottom: 10px; word-wrap: break-word;">
          ${explanation}
        </div>
      `;
    }

    // Signals
    const list = shadow.getElementById("signals-list");
    list.innerHTML = "";
    (signals || []).forEach(({ engine, score: s, flags }) => {
      const cls = s >= 70 ? "sig-high" : s >= 40 ? "sig-mid" : "sig-low";
      const div = document.createElement("div");
      div.className = "signal-item";
      div.innerHTML = `
        <div>
          <div class="signal-engine">${engineLabel(engine)}</div>
          <div class="signal-flags">${(flags || []).join(", ") || "—"}</div>
        </div>
        <span class="signal-score ${cls}">${s}</span>
      `;
      list.appendChild(div);
    });

    // Remove existing details if they were appended before
    const existingDetails = shadow.getElementById("extra-details-container");
    if (existingDetails) existingDetails.remove();

    if (urlHtml || expHtml) {
      const detailsContainer = document.createElement("div");
      detailsContainer.id = "extra-details-container";
      detailsContainer.innerHTML = urlHtml + expHtml;
      list.parentNode.insertBefore(detailsContainer, list.nextSibling);
    }

    shadow.getElementById("cached-note").textContent = cached ? "⚡ Cached result" : "";
    setState(shadow, "result");
  }

  function engineLabel(engine) {
    return { url: "🔗 URL Analysis", nlp: "🧠 Body / NLP", headers: "📋 Headers", attachments: "📎 Attachments" }[engine] || engine;
  }

  // ─── Sidebar bootstrap ────────────────────────────────────────────────────

  function injectSidebar() {
    if (document.getElementById("phishing-detector-host")) return;

    const { host, shadow } = createSidebar();
    document.body.appendChild(host);
    sidebar = { host, shadow };

    // Collapse toggle
    let collapsed = false;
    shadow.getElementById("header").addEventListener("click", () => {
      collapsed = !collapsed;
      shadow.getElementById("body").style.display = collapsed ? "none" : "block";
      shadow.getElementById("collapse-btn").textContent = collapsed ? "+" : "−";
    });

    // Scan button
    shadow.getElementById("scan-btn").addEventListener("click", () => triggerScan());

    // Retry button
    shadow.getElementById("retry-btn").addEventListener("click", () => triggerScan());
  }

  function removeSidebar() {
    const host = document.getElementById("phishing-detector-host");
    if (host) host.remove();
    sidebar = null;
  }

  // ─── Scan flow ────────────────────────────────────────────────────────────

  function triggerScan() {
    if (!currentMessageId || !sidebar) return;

    setState(sidebar.shadow, "scanning");

    chrome.runtime.sendMessage(
      { type: "SCAN_EMAIL", messageId: currentMessageId },
      (response) => {
        if (!sidebar) return; // Sidebar closed between request and response

        if (!response || !response.ok) {
          sidebar.shadow.getElementById("error-msg").textContent =
            response?.error || "Unknown error. Check console.";
          setState(sidebar.shadow, "error");
          return;
        }

        renderResult(sidebar.shadow, response.result);
      }
    );
  }

  // ─── Gmail navigation watcher ─────────────────────────────────────────────

  /**
   * Gmail is a SPA — it doesn't reload on email open.
   * We watch hash changes + MutationObserver on the main content area.
   */
  function handleNavigation() {
    const msgId = extractMessageId();

    if (msgId && msgId !== currentMessageId) {
      currentMessageId = msgId;
      injectSidebar();
      // Reset to idle state for new email
      if (sidebar) setState(sidebar.shadow, "idle");
    } else if (!msgId && currentMessageId) {
      // Left the email view
      currentMessageId = null;
      removeSidebar();
    }
  }

  function startObserver() {
    // Watch URL hash changes (Gmail navigation)
    window.addEventListener("hashchange", handleNavigation);

    // Also watch DOM for Gmail's dynamic rendering
    const target = document.body;
    observer = new MutationObserver(() => handleNavigation());
    observer.observe(target, { childList: true, subtree: true });

    // Initial check
    handleNavigation();
  }

  // ─── Init ─────────────────────────────────────────────────────────────────

  // Wait for Gmail to finish initial render
  if (document.readyState === "complete") {
    startObserver();
  } else {
    window.addEventListener("load", startObserver);
  }
})();
