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

      // Priority 1: direct HTML part
      if (mime === 'text/html' && part.body?.data) {
        return Buffer.from(part.body.data, 'base64').toString('utf-8');
      }

      // Priority 2: nested multipart — recurse
      if (part.parts) {
        const deep = getBody(part);
        if (deep) return deep;
      }
    }

    // Fallback: plain text if no HTML found
    for (const part of payload.parts) {
      if (part.mimeType === 'text/plain' && part.body?.data) {
        return Buffer.from(part.body.data, 'base64').toString('utf-8');
      }
    }
  } else {
    // Single-part message
    if (payload.mimeType === 'text/html' && payload.body?.data) {
      return Buffer.from(payload.body.data, 'base64').toString('utf-8');
    }
  }
  return '';
}

async function fetchLatestEmails(accessToken, maxResults = 2) {
  const service = getGmailService(accessToken);

  const listRes = await service.users.messages.list({
    userId: 'me',
    maxResults,
  });

  const messages = listRes.data.messages || [];
  const emailData = [];

  for (const msg of messages) {
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
    
    // Convert headers array into a plain text string for the AI DNA Agent
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
  } // <-- This is the brace that usually gets deleted!

  return emailData;
} // <-- Or this one!

module.exports = { fetchLatestEmails };