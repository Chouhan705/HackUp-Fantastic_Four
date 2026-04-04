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
    host.id    = "phishing-detector-host";
    host.style.cssText = `
      position: fixed;
      top: 120px;
      right: 0;
      width: 300px;
      z-index: 9999;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    `;

    const shadow = host.attachShadow({ mode: "open" });

    shadow.innerHTML = `
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }

        #panel {
          background: #fff;
          border: 1px solid #e0e0e0;
          border-right: none;
          border-radius: 12px 0 0 12px;
          box-shadow: -4px 4px 24px rgba(0,0,0,0.10);
          overflow: hidden;
          transition: width 0.25s ease;
        }

        #header {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 12px 14px;
          background: #f8f8f6;
          border-bottom: 1px solid #ebebeb;
          cursor: pointer;
          user-select: none;
        }
        #header-icon { font-size: 18px; }
        #header-title { font-size: 13px; font-weight: 600; color: #1a1a18; flex: 1; }
        #collapse-btn { font-size: 16px; color: #888; line-height: 1; }

        #body { padding: 14px; }

        /* States */
        #state-idle, #state-scanning, #state-result, #state-error { display: none; }
        #state-idle.active, #state-scanning.active,
        #state-result.active, #state-error.active { display: block; }

        #scan-btn {
          width: 100%;
          padding: 9px 0;
          background: #1a73e8;
          color: #fff;
          border: none;
          border-radius: 8px;
          font-size: 13px;
          font-weight: 500;
          cursor: pointer;
          transition: background 0.15s;
        }
        #scan-btn:hover { background: #1558c0; }

        .scanning-text {
          font-size: 13px;
          color: #555;
          text-align: center;
          padding: 8px 0;
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
          padding: 4px 12px;
          border-radius: 100px;
          font-size: 12px;
          font-weight: 600;
          margin-bottom: 12px;
        }
        .verdict-safe      { background: #eaf3de; color: #3b6d11; }
        .verdict-suspicious{ background: #faeeda; color: #854f0b; }
        .verdict-phishing  { background: #fcebeb; color: #a32d2d; }

        .score-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 10px;
        }
        .score-label { font-size: 12px; color: #666; }
        .score-val   { font-size: 22px; font-weight: 700; color: #1a1a18; }

        .score-bar-track {
          height: 6px;
          background: #eee;
          border-radius: 3px;
          margin-bottom: 14px;
          overflow: hidden;
        }
        .score-bar-fill {
          height: 100%;
          border-radius: 3px;
          transition: width 0.6s ease;
        }

        .signals-title { font-size: 11px; font-weight: 600; color: #888; letter-spacing: .05em; text-transform: uppercase; margin-bottom: 8px; }
        .signal-item {
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 7px 10px;
          background: #f8f8f6;
          border-radius: 7px;
          margin-bottom: 6px;
        }
        .signal-engine { font-size: 12px; font-weight: 500; color: #333; }
        .signal-score  { font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 100px; }
        .signal-flags  { font-size: 11px; color: #888; margin-top: 2px; }

        .sig-high { background: #fcebeb; color: #a32d2d; }
        .sig-mid  { background: #faeeda; color: #854f0b; }
        .sig-low  { background: #eaf3de; color: #3b6d11; }

        .cached-note { font-size: 10px; color: #bbb; text-align: right; margin-top: 10px; }

        .error-text { font-size: 12px; color: #a32d2d; line-height: 1.5; }
        .retry-btn {
          margin-top: 10px;
          font-size: 12px;
          padding: 6px 14px;
          border: 1px solid #e24b4a;
          background: transparent;
          color: #a32d2d;
          border-radius: 7px;
          cursor: pointer;
        }
      </style>

      <div id="panel">
        <div id="header">
          <span id="header-icon">🛡️</span>
          <span id="header-title">Phishing Detector</span>
          <span id="collapse-btn">−</span>
        </div>
        <div id="body">
          <!-- IDLE: waiting for user to trigger scan -->
          <div id="state-idle" class="active">
            <p style="font-size:12px;color:#666;margin-bottom:12px;line-height:1.5">
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
    const { score, verdict, signals, cached } = result;

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

    shadow.getElementById("cached-note").textContent = cached ? "⚡ Cached result" : "";
    setState(shadow, "result");
  }

  function engineLabel(engine) {
    return { url: "🔗 URL Analysis", nlp: "🧠 Body / NLP", headers: "📋 Headers" }[engine] || engine;
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
