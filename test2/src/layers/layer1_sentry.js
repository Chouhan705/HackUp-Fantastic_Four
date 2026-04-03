/**
 * Layer 1: The Local Sentry (Deterministic Filter)
 * Goal: Instant detection to save API costs and latency.
 */

// Heuristic Regex Patterns
const PUNYCODE_REGEX = /xn--/i;
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF]/g;
const URGENT_WORDS = /\b(urgent|immediate|account suspended|verify|action required|password reset)\b/gi;
const URGENT_DENSITY_THRESHOLD = 3;

function detectObfuscation(text) {
  // \u200B is the Zero-Width Space. 
  // Let's check if it's being used to break up sensitive words.
  const suspiciousPattern = /(p\u200B?a\u200B?y\u200B?p\u200B?a\u200B?l|l\u200B?o\u200B?g\u200B?i\u200B?n)/i;
  
  const zeroWidthCount = (text.match(/[\u200B-\u200D\uFEFF]/g) || []).length;

  // Rule: Only block if there are more than 5, or if they break a keyword (using 10 as buffer).
  if (suspiciousPattern.test(text) || zeroWidthCount > 10) {
    return true; // Likely a real attack
  }
  return false; // Likely technical noise from LinkedIn/Google
}

/**
 * Preprocess the email to check for obvious, critical threats locally.
 * @param {Object} email { headers: { from, replyTo }, body, urls }
 * @returns {Object} { isCritical: boolean, reason: string | null }
 */
function localSentry(email) {
  const { headers, body, urls } = email;
  const flags = [];

  // 1. Punycode Check (Typosquatting/Homograph Attacks)
  for (const url of urls) {
    if (PUNYCODE_REGEX.test(url)) {
      return { isCritical: true, reason: `Homograph attack detected using Punycode in URL: ${url}`, flags };
    }
  }

  // 2. Hidden Zero-Width Characters (FLAG ONLY, DO NOT BLOCK)
  if (detectObfuscation(body) || detectObfuscation(headers.from)) {
    flags.push("obfuscation_detected");
  }

  // 3. Mismatched Reply-To vs From
  if (headers.replyTo && headers.from) {
    const extractDomain = (addr) => (addr.match(/@([\w.-]+)/) || [])[1];        
    const fromDomain = extractDomain(headers.from);
    const replyDomain = extractDomain(headers.replyTo);

    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      if (!isKnownMailingList(fromDomain, replyDomain)) {
         return { isCritical: true, reason: `Suspicious: 'From' domain (${fromDomain}) does not match 'Reply-To' domain (${replyDomain}).`, flags };
      }
    }
  }

  // 4. "Urgent" Keyword Density
  const urgentMatches = (body.match(URGENT_WORDS) || []).length;
  if (urgentMatches >= URGENT_DENSITY_THRESHOLD) {
    // Flag it, but don't block
    flags.push("high_urgency");
  }

  return { isCritical: false, reason: null, flags };
}

// Mock whitelist
function isKnownMailingList() {
    return false;
}

module.exports = { localSentry };
