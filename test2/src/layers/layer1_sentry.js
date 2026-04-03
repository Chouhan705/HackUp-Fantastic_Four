/**
 * Layer 1: The Local Sentry (Deterministic Filter)
 * Goal: Instant detection to save API costs and latency.
 */

// Heuristic Regex Patterns
const PUNYCODE_REGEX = /xn--/i;
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF]/g;
const URGENT_WORDS = /\b(urgent|immediate|account suspended|verify|action required|password reset)\b/gi;
const URGENT_DENSITY_THRESHOLD = 3;

/**
 * Preprocess the email to check for obvious, critical threats locally.
 * @param {Object} email { headers: { from, replyTo }, body, urls }
 * @returns {Object} { isCritical: boolean, reason: string | null }
 */
function localSentry(email) {
  const { headers, body, urls } = email;

  // 1. Punycode Check (Typosquatting/Homograph Attacks)
  for (const url of urls) {
    if (PUNYCODE_REGEX.test(url)) {
      return { isCritical: true, reason: `Homograph attack detected using Punycode in URL: ${url}` };
    }
  }

  // 2. Hidden Zero-Width Characters
  if (ZERO_WIDTH_REGEX.test(body) || ZERO_WIDTH_REGEX.test(headers.from)) {
    return { isCritical: true, reason: "Obfuscation detected via zero-width characters." };
  }

  // 3. Mismatched Reply-To vs From
  if (headers.replyTo && headers.from) {
    const extractDomain = (addr) => (addr.match(/@([\w.-]+)/) || [])[1];
    const fromDomain = extractDomain(headers.from);
    const replyDomain = extractDomain(headers.replyTo);
    
    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      if (!isKnownMailingList(fromDomain, replyDomain)) {
         return { isCritical: true, reason: `Suspicious: 'From' domain (${fromDomain}) does not match 'Reply-To' domain (${replyDomain}).` };
      }
    }
  }

  // 4. "Urgent" Keyword Density
  const urgentMatches = (body.match(URGENT_WORDS) || []).length;
  if (urgentMatches >= URGENT_DENSITY_THRESHOLD) {
    // Note: High urgency alone isn't always critical, but for this exercise we flag it
    // Usually, this would just be fed to Layer 3, but let's assume it's a critical local heuristic
    console.warn(`[Local Sentry] High urgency keyword density detected (${urgentMatches} words).`);
  }

  return { isCritical: false, reason: null };
}

// Mock whitelist
function isKnownMailingList() {
    return false;
}

module.exports = { localSentry };
