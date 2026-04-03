/**
 * ─── LIFECYCLE MANAGEMENT ───
 */
chrome.runtime.onInstalled.addListener(({ reason }) => {
    if (reason === "install") {
        console.log("🛡️ [PhishGuard.AI] Extension Installed. Initializing secure storage...");
        chrome.storage.local.set({ 
            scanHistory: [], 
            authToken: null 
        });
    }
});

/**
 * ─── PERSISTENCE (HEARTBEAT) ───
 * MV3 Service Workers shut down after 30s of inactivity. 
 * We use an alarm to "nudge" the worker every minute to stay active for live monitoring.
 */
chrome.alarms.create('keepAlive', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'keepAlive') {
        console.log('💓 [PhishGuard.AI] Heartbeat: Service Worker is active.');
    }
});

/**
 * ─── SILENT AUTHENTICATION ───
 * Attempts to restore the user's session whenever Chrome starts up.
 */
chrome.runtime.onStartup.addListener(async () => {
    console.log("🚀 [PhishGuard.AI] Browser started. Restoring session...");
    const token = await getAuthTokenSilent();
    if (token) {
        chrome.storage.local.set({ authToken: token });
    }
});

function getAuthTokenSilent() {
    return new Promise((resolve) => {
        chrome.identity.getAuthToken({ interactive: false }, (token) => {
            if (chrome.runtime.lastError || !token) {
                console.log("⚠️ [Auth] No cached session found.");
                resolve(null);
            } else {
                console.log("✅ [Auth] Session restored successfully.");
                resolve(token);
            }
        });
    });
}

/**
 * ─── MESSAGE ROUTING ───
 * Bridges communication between the Content Script (Gmail) and the Extension UI.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Forward Gmail email-open events to the Popup or Side Panel
    if (message.type === "EMAIL_OPENED") {
        console.log("📨 [Background] Relaying target email ID:", message.emailId);
        // We broadcast this so if the Side Panel is open, it can react immediately
        chrome.runtime.sendMessage(message);
    }

    // Handle manual auth requests if needed
    if (message.type === "GET_TOKEN_INTERACTIVE") {
        chrome.identity.getAuthToken({ interactive: true }, (token) => {
            sendResponse({ token: token || null });
        });
        return true; // Keep channel open for async response
    }
});