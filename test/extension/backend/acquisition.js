/**
 * 📥 PhishGuard.AI — Data Acquisition Layer
 * Role: Interfaces with the Gmail API to retrieve email DNA for forensic analysis.
 */
const { google } = require('googleapis');

/**
 * Initializes the Gmail API service using the OAuth2 access token from the extension.
 */
function getGmailService(accessToken) {
  const auth = new google.auth.OAuth2();
  auth.setCredentials({ access_token: accessToken });
  return google.gmail({ version: 'v1', auth });
}

/**
 * RECURSIVE MIME PARSER
 * Forensic emails often have multiple layers (Multipart/Alternative, Multipart/Related).
 * This function drills down to find the actual HTML or Plain Text content.
 */
function getBody(payload) {
  if (payload.parts) {
    for (const part of payload.parts) {
      const mime = part.mimeType || '';
      
      // Priority 1: HTML Body
      if (mime === 'text/html' && part.body?.data) {
        return Buffer.from(part.body.data, 'base64').toString('utf-8');
      }
      
      // Priority 2: Recurse into nested parts
      if (part.parts) {
        const deep = getBody(part);
        if (deep) return deep;
      }
    }
    
    // Fallback: Plain Text if HTML is missing
    for (const part of payload.parts) {
      if (part.mimeType === 'text/plain' && part.body?.data) {
        return Buffer.from(part.body.data, 'base64').toString('utf-8');
      }
    }
  } else {
    // Handling for simple, single-part emails
    if (payload.mimeType === 'text/html' && payload.body?.data) {
      return Buffer.from(payload.body.data, 'base64').toString('utf-8');
    }
  }
  return '';
}

/**
 * FETCH LATEST EMAILS (Batch Mode)
 * Implements Deduplication: Skips IDs that the extension has already validated.
 */
async function fetchLatestEmails(accessToken, maxResults = 5, existingIds = []) {
  const service = getGmailService(accessToken);
  const idSet = new Set(existingIds); // O(1) lookup for high-speed filtering

  console.log(`📡 [Acquisition] Requesting list (Limit: ${maxResults})...`);

  const listRes = await service.users.messages.list({
    userId: 'me',
    maxResults,
  });

  const messages = listRes.data.messages || [];
  const emailData = [];

  for (const msg of messages) {
    // 🛡️ DEDUPLICATION CHECK: Skip redundant processing
    if (idSet.has(msg.id)) {
      console.log(`⏩ [Acquisition] Skipping known ID: ${msg.id}`);
      continue;
    }

    console.log(`📥 [Acquisition] Fetching full DNA for ID: ${msg.id}`);
    
    const full = await service.users.messages.get({
      userId: 'me',
      id: msg.id,
      format: 'full',
    });

    const payload = full.data.payload || {};
    const headers = payload.headers || [];

    // Metadata extraction for UI mapping
    const subject = headers.find(h => h.name.toLowerCase() === 'subject')?.value || 'No Subject';
    const sender  = headers.find(h => h.name.toLowerCase() === 'from')?.value  || 'Unknown';
    const date    = headers.find(h => h.name.toLowerCase() === 'date')?.value  || '';

    const htmlBody = getBody(payload);
    
    // Combine all headers into a single block for the DNA Detective agent
    const rawHeadersText = headers.map(h => `${h.name}: ${h.value}`).join('\n');

    emailData.push({
      id:        msg.id,
      subject,
      sender,
      date,
      snippet:   full.data.snippet || '',
      full_html: htmlBody,
      headers:   rawHeadersText 
    });
  }

  return emailData;
}

/**
 * FETCH SINGLE EMAIL (Auto-Scan Mode)
 * Triggered by the extension when a user clicks a specific email in Gmail.
 */
async function fetchSingleEmail(accessToken, emailId) {
  const service = getGmailService(accessToken);
  
  console.log(`🎯 [Acquisition] Targeted fetch for ID: ${emailId}`);

  const full = await service.users.messages.get({
    userId: 'me',
    id: emailId,
    format: 'full',
  });

  const payload = full.data.payload || {};
  const headers = payload.headers || [];

  const subject = headers.find(h => h.name.toLowerCase() === 'subject')?.value || 'No Subject';
  const sender  = headers.find(h => h.name.toLowerCase() === 'from')?.value  || 'Unknown';
  const date    = headers.find(h => h.name.toLowerCase() === 'date')?.value  || '';

  return {
    id:        emailId,
    subject,
    sender,
    date,
    snippet:   full.data.snippet || '',
    full_html: getBody(payload),
    headers:   headers.map(h => `${h.name}: ${h.value}`).join('\n')
  };
}

module.exports = { fetchLatestEmails, fetchSingleEmail };