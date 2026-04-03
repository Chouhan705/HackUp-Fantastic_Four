// extraction.js
const cheerio = require('cheerio');
const { URL } = require('url');

const SHORTENERS  = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'ow.ly', 'buff.ly'];
const BRANDS      = ['google', 'netflix', 'paypal', 'amazon', 'microsoft', 'upi', 'paytm', 'apple', 'facebook', 'stripe', 'shopify'];
const URGENCY_KW  = ['urgent', 'suspend', 'restricted', 'unauthorized', 'action required', 'login now', 'verify', 'security alert', 'locked', 'immediately'];

// Domains that are widely trusted but aren't specific "Brands" we monitor for impersonation
const GLOBAL_TRUST_LIST = [
  'google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'stripe.com', 
  'shopify.com', 'linkedin.com', 'github.com', 'dropbox.com', 'zoom.us', 
  'slack.com', 'cloudflare.com', 'adobe.com', 'salesforce.com'
];

// campaign signature generation
function generateCampaignSignature(mailObj, $) {
  // 1. Structural Fingerprint (The tags only, no text)
  const structure = $('*').map((i, el) => el.tagName).get().join('');
  
  // 2. URL Skeleton (Domain + Path, no query params)
  const urlSkeletons = $('a[href]').map((i, el) => {
      try {
          const u = new URL($(el).attr('href'));
          return u.hostname + u.pathname;
      } catch { return null; }
  }).get().filter(Boolean).sort().join('|');

  // 3. Metadata Hash
  return {
      structure_hash: structure.length, // Simple version: length of tag string
      url_footprint: urlSkeletons,
      subject_pattern: (mailObj.subject || "").replace(/[0-9]/g, 'X') // Remove numbers
  };
}

function extractData(mailObj) {
  let html = mailObj.full_html || '';
  if (!html) html = `<html><body>${mailObj.snippet || ''}</body></html>`;

  const $ = cheerio.load(html);
  const textContent = $.text().toLowerCase();
  const cleanTextForAI = $.text().replace(/\s+/g, ' ').trim();

  // Helper to extract a domain safely for comparison
  const getDomain = (urlStr) => {
    try {
      if (!urlStr || urlStr.length < 4) return null;
      // Handle cases where text might be "paypal.com" (no protocol)
      const u = new URL(urlStr.includes('://') ? urlStr : `http://${urlStr}`);
      return u.hostname.toLowerCase().replace('www.', '');
    } catch { return null; }
  };

  const features = {
    url_count: 0,
    ip_as_url: 0,
    shortened_url: 0,
    deceptive_link: 0,   // Explicit Lying (Text: "google.com" -> Link: "evil.com")
    untrusted_link: 0,   // Unknown destination (Not a brand, not in Trust List)
    urgency_score: 0,
    brand_impersonation: 0,
    has_form: $('form').length > 0 ? 1 : 0,
    has_password_input: $('input[type="password"]').length > 0 ? 1 : 0,
  };

  const extractedUrls = [];

  // ── URL & LINK ANALYSIS ──────────────────
  const links = $('a[href]').toArray();
  features.url_count = links.length;

  for (const el of links) {
    const href = $(el).attr('href') || '';
    const linkText = $(el).text().trim().toLowerCase();
    
    extractedUrls.push(href);
    const hrefDomain = getDomain(href);
    const textDomain = getDomain(linkText); // Extracts a domain IF the visible text looks like a URL

    if (!hrefDomain) continue;

    // 1. Detect IP-based URLs (Critical Indicator)
    if (/\d+\.\d+\.\d+\.\d+/.test(hrefDomain)) features.ip_as_url = 1;

    // 2. Detect URL Shorteners
    if (SHORTENERS.some(s => hrefDomain.includes(s))) features.shortened_url += 1;

    // 3. TIED DECEPTION LOGIC
    
    // A: THE VISUAL SPOOF (Text: "paypal.com" | Link: "hacker.com")
    if (textDomain && hrefDomain !== textDomain) {
      features.deceptive_link = 1; 
    }

    // B: THE BRAND HIJACK (Text: "Netflix Login" | Link: "random-site.net")
    const textMentionsBrand = BRANDS.some(b => linkText.includes(b));
    const hrefIsBrand = BRANDS.some(b => hrefDomain.includes(b));
    if (textMentionsBrand && !hrefIsBrand) {
      features.deceptive_link = 1;
    }

    // C: THE UNTRUSTED CHECK (Unknown Small Scale Entities)
    const isInTrustList = GLOBAL_TRUST_LIST.some(d => hrefDomain.includes(d));
    if (!hrefIsBrand && !isInTrustList && !features.deceptive_link) {
      // It's not a major brand, not in our trust list, and hasn't lied yet.
      features.untrusted_link = 1;
    }
  }

  // ── SENDER ANALYSIS ──────────────────
  const senderStr = (mailObj.sender || "").toLowerCase();
  const senderName = senderStr.split('<')[0].replace(/['"]+/g, '').trim();
  const isFreemail = /gmail\.com|outlook\.com|yahoo\.com|hotmail\.com|icloud\.com/.test(senderStr);
  
  // ── SUBJECT & BRAND ANALYSIS ──────────────────
  const subject = (mailObj.subject || "").toLowerCase();
  const mentionsBrandInBody = BRANDS.find(b => textContent.includes(b));
  const mentionsBrandInSubject = BRANDS.find(b => subject.includes(b));
  
  // High risk: Brand name in sender display name OR subject, but using freemail
  if (isFreemail && (BRANDS.some(b => senderName.includes(b)) || mentionsBrandInSubject)) {
    features.brand_impersonation = 1; 
  }

  // ── URGENCY ANALYSIS (Body + Subject) ──
  const urgencyInBody = URGENCY_KW.filter(w => textContent.includes(w));
  const urgencyInSubject = URGENCY_KW.filter(w => subject.includes(w));
  features.urgency_score = [...new Set([...urgencyInBody, ...urgencyInSubject])].length;

  return {
    headers: mailObj.headers || "",
    sender: mailObj.sender || "",
    sender_name: senderName,
    subject: mailObj.subject || "",
    clean_text: cleanTextForAI,
    urls: extractedUrls,
    attachments: mailObj.attachments || [], 
    heuristic_features: features,
    is_freemail: isFreemail,
    mentions_brand: mentionsBrandInBody || mentionsBrandInSubject || "",
    heuristic_score: 0 // Placeholder for agents.js to calculate
  };
}

module.exports = { extractData };