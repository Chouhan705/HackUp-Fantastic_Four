/**
 * Security: Mask all PII (usernames, specific phone numbers) before sending data to the Gemini API.
 */

const EMAIL_REGEX = /([a-zA-Z0-9._-]+)@([a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/gi;
const PHONE_REGEX = /(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}/g;

/**
 * Mask PII from the email headers and body.
 * @param {Object} email { headers, body, urls }
 * @returns {Object} Safe Email
 */
function maskPII(email) {
  let maskedBody = email.body || "";
  let maskedHeaders = {};

  // Mask Phone numbers: 555-123-4567 -> ***-***-****
  maskedBody = maskedBody.replace(PHONE_REGEX, "[REDACTED PHONE]");

  // Mask Email Addresses (keep domain): john.doe@example.com -> j***@example.com
  maskedBody = maskedBody.replace(EMAIL_REGEX, (match, user, domain) => {
    return `[REDACTED_USER]@${domain}`;
  });

  // Mask Headers
  if (email.headers) {
    for (const [key, value] of Object.entries(email.headers)) {
      if (typeof value === 'string') {
        let maskedValue = value.replace(PHONE_REGEX, "[REDACTED PHONE]");
        maskedValue = maskedValue.replace(EMAIL_REGEX, (match, user, domain) => {
          return `[REDACTED_USER]@${domain}`;
        });
        maskedHeaders[key] = maskedValue;
      } else {
        maskedHeaders[key] = value;
      }
    }
  }

  return {
    headers: email.headers ? maskedHeaders : {},
    body: maskedBody,
    urls: email.urls
  };
}

module.exports = { maskPII };
