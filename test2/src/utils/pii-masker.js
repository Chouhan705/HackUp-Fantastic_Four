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
  let maskedBody = email.body;

  // Mask Phone numbers: 555-123-4567 -> ***-***-****
  maskedBody = maskedBody.replace(PHONE_REGEX, "[REDACTED PHONE]");

  // Mask Email Addresses (keep domain): john.doe@example.com -> j***@example.com
  maskedBody = maskedBody.replace(EMAIL_REGEX, (match, user, domain) => {
    return `[REDACTED_USER]@${domain}`;
  });

  return {
    headers: email.headers,
    body: maskedBody,
    urls: email.urls
  };
}

module.exports = { maskPII };
