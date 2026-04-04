// background/service_worker.js
// Handles: OAuth2 token management, Gmail API raw fetch, backend communication

const BACKEND_URL = "http://localhost:8000"; // 🔧 Configured for local FastAPI backend
const GMAIL_API   = "https://gmail.googleapis.com/gmail/v1/users/me";

// ─── OAuth2 Token ────────────────────────────────────────────────────────────

async function getAuthToken(interactive = false) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        reject(chrome.runtime.lastError?.message || "No token");
      } else {
        resolve(token);
      }
    });
  });
}

async function fetchWithAuth(url, token, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  // Token expired → remove cached token and retry once
  if (res.status === 401) {
    await new Promise((resolve) =>
      chrome.identity.removeCachedAuthToken({ token }, resolve)
    );
    const freshToken = await getAuthToken(false);
    return fetch(url, {
      ...options,
      headers: {
        Authorization: `Bearer ${freshToken}`,
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
  }

  return res;
}

// ─── Gmail API ───────────────────────────────────────────────────────────────

/**
 * Fetches the raw (base64url encoded) email by messageId.
 * Returns the base64url string or throws.
 */
async function fetchRawEmail(messageId) {
  const token = await getAuthToken(false);
  const url   = `${GMAIL_API}/messages/${messageId}?format=raw`;
  const res   = await fetchWithAuth(url, token);

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Gmail API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  // data.raw is base64url encoded full RFC 2822 message
  return data.raw;
}

// ─── Backend Communication ───────────────────────────────────────────────────

/**
 * Sends raw email to your backend orchestrator.
 * Expects: { score, verdict, confidence, signals } in response.
 */
async function scanEmail(messageId, rawEmail) {
  const res = await fetch(`${BACKEND_URL}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message_id: messageId, raw_email: rawEmail }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Backend error ${res.status}: ${err}`);
  }

  return res.json();
}

// ─── Cache ───────────────────────────────────────────────────────────────────

// Simple in-memory cache for the current session (keyed by messageId)
const scanCache = new Map();

async function getCachedOrScan(messageId) {
  if (scanCache.has(messageId)) {
    return { cached: true, ...scanCache.get(messageId) };
  }

  const rawEmail = await fetchRawEmail(messageId);
  const result   = await scanEmail(messageId, rawEmail);
  scanCache.set(messageId, result);
  return { cached: false, ...result };
}

// ─── Message Handler (from content script) ───────────────────────────────────

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "SCAN_EMAIL") {
    const { messageId } = msg;

    getCachedOrScan(messageId)
      .then((result) => sendResponse({ ok: true, result }))
      .catch((err)   => sendResponse({ ok: false, error: err.message }));

    return true; // Keep channel open for async response
  }

  if (msg.type === "GET_AUTH_TOKEN") {
    getAuthToken(true)
      .then((token) => sendResponse({ ok: true, token }))
      .catch((err)  => sendResponse({ ok: false, error: err.message }));

    return true;
  }
});
