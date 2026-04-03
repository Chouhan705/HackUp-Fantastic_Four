// acquisition.js
const { google } = require('googleapis');

function getGmailService(accessToken) {
  const auth = new google.auth.OAuth2();
  auth.setCredentials({ access_token: accessToken });
  return google.gmail({ version: 'v1', auth });
}

// Recursively drills into MIME payload to find HTML body
function getBody(payload) {
  if (payload.parts) {
    for (const part of payload.parts) {
      const mime = part.mimeType || '';
      if (mime === 'text/html' && part.body?.data) {
        return Buffer.from(part.body.data, 'base64').toString('utf-8');
      }
      if (part.parts) {
        const deep = getBody(part);
        if (deep) return deep;
      }
    }
    for (const part of payload.parts) {
      if (part.mimeType === 'text/plain' && part.body?.data) {
        return Buffer.from(part.body.data, 'base64').toString('utf-8');
      }
    }
  } else {
    if (payload.mimeType === 'text/html' && payload.body?.data) {
      return Buffer.from(payload.body.data, 'base64').toString('utf-8');
    }
  }
  return '';
}

/**
 * Fetches the latest emails but SKIPS those already in existingIds
 */
async function fetchLatestEmails(accessToken, maxResults = 5, existingIds = []) {
  const service = getGmailService(accessToken);
  const idSet = new Set(existingIds); // Use a Set for O(1) lookup speed

  const listRes = await service.users.messages.list({
    userId: 'me',
    maxResults,
  });

  const messages = listRes.data.messages || [];
  const emailData = [];

  for (const msg of messages) {
    // RESOURCE CHECK: Skip if already scanned to save API quota and time
    if (idSet.has(msg.id)) {
      console.log(`[Acquisition] Skipping duplicate ID: ${msg.id}`);
      continue;
    }

    const full = await service.users.messages.get({
      userId: 'me',
      id: msg.id,
      format: 'full',
    });

    const payload = full.data.payload || {};
    const headers = payload.headers || [];

    const subject = headers.find(h => h.name.toLowerCase() === 'subject')?.value || 'No Subject';
    const sender  = headers.find(h => h.name.toLowerCase() === 'from')?.value  || 'Unknown';
    const date    = headers.find(h => h.name.toLowerCase() === 'date')?.value  || '';

    const htmlBody = getBody(payload);
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
 * Fetches a specific email by ID (for the "Auto-Scan" feature)
 */
async function fetchSingleEmail(accessToken, emailId) {
  const service = getGmailService(accessToken);

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