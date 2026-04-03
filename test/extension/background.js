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
 