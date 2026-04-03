// background.js — PhishGuard.AI Service Worker (Manifest V3)
 
// ─── Lifecycle ────────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") {
    console.log("[PhishGuard.AI] Extension installed.");
    chrome.storage.local.set({ authToken: null, lastScan: null });
  }
});
 
// ─── Message router ───────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_EMAIL") {
    analyzeEmail(message.payload).then(sendResponse);
    return true; // async response
  }
 
  if (message.type === "GET_AUTH_TOKEN") {
    chrome.identity.getAuthToken({ interactive: true }, (token) => {
      if (chrome.runtime.lastError) {
        sendResponse({ error: chrome.runtime.lastError.message });
      } else {
        chrome.storage.local.set({ authToken: token });
        sendResponse({ token });
      }
    });
    return true;
  }
});
 
// ─── Mock AI email analysis (replace with real API call) ──────────────────────
async function analyzeEmail(emailPayload) {
  // In production: call your AI backend or Google's Safe Browsing API here
  // Example:
  //   const res = await fetch("https://your-api.com/analyze", {
  //     method: "POST",
  //     headers: { "Content-Type": "application/json" },
  //     body: JSON.stringify(emailPayload),
  //   });
  //   return res.json();
 
  return {
    score: 88,
    summary: "Suspicious Link Detected",
    detail: "The link leads to 'paypa1.com' instead of 'paypal.com'. Classic homograph phishing.",
    sender: "support@paypa1.com",
    subject: "Urgent: Verify Your Account",
  };
}
 // Create an alarm every 1 minute to keep the worker "hot"
chrome.alarms.create('keepAlive', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    console.log('[PhishGuard.AI] Heartbeat: Worker is active.');
  }
});// background.js

chrome.runtime.onStartup.addListener(() => {
    chrome.identity.getAuthToken({ interactive: false }, (token) => {
        if (chrome.runtime.lastError || !token) {
            console.log("[PhishGuard.AI] No active session found on startup.");
        } else {
            console.log("[PhishGuard.AI] Session validated silently.");
        }
    });
});
// background.js
function getAuthTokenSilent() {
  return new Promise((resolve) => {
    chrome.identity.getAuthToken({ interactive: false }, (token) => {
      if (chrome.runtime.lastError || !token) {
        console.log("[PhishGuard.AI] No cached session found.");
        resolve(null);
      } else {
        console.log("[PhishGuard.AI] Session restored.");
        resolve(token);
      }
    });
  });
}

// Check on startup
chrome.runtime.onStartup.addListener(async () => {
  const token = await getAuthTokenSilent();
  if (token) {
    chrome.storage.local.set({ authToken: token });
  }
});