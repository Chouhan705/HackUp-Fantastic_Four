// extraction.js
const cheerio = require('cheerio');
const { URL } = require('url');

const SHORTENERS  = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'ow.ly', 'buff.ly'];
const BRANDS      = ['google', 'netflix', 'paypal', 'amazon', 'microsoft', 'upi', 'paytm', 'apple', 'facebook'];
const URGENCY_KW  = ['urgent', 'suspend', 'restricted', 'unauthorized', 'action required', 'login now', 'verify', 'security alert'];

function extractData(mailObj) {
  let html = mailObj.full_html || '';
  if (!html) html = `<html><body>${mailObj.snippet || ''}</body></html>`;

  const $ = cheerio.load(html);
  const textContent = $.text().toLowerCase();
  const cleanTextForAI = $.text().replace(/\s+/g, ' ').trim(); // Cleaned for Agent C

  const features = {
    url_count: 0,
    ip_as_url: 0,
    shortened_url: 0,
    link_mismatch: 0,
    urgency_score: 0,
    brand_impersonation: 0,
    has_form: $('form').length > 0 ? 1 : 0,
    has_password_input: $('input[type="password"]').length > 0 ? 1 : 0,
  };

  const extractedUrls = []; // Clean array for Agent B

  // ── URL Analysis ──────────────────
  const links = $('a[href]').toArray();
  features.url_count = links.length;

  for (const el of links) {
    const href = $(el).attr('href') || '';
    extractedUrls.push(href);
    
    const linkText = $(el).text().toLowerCase();
    let domain = '';

    try {
      domain = new URL(href).hostname.toLowerCase();
    } catch {
      continue;
    }

    if (/\d+\.\d+\.\d+\.\d+/.test(domain)) features.ip_as_url = 1;
    if (SHORTENERS.some(s => domain.includes(s))) features.shortened_url += 1;
    
    if (BRANDS.some(b => linkText.includes(b)) && domain && !BRANDS.some(b => domain.includes(b))) {
      features.link_mismatch += 1;
    }
  }

  // ── NLP Features ──────────────────
  features.urgency_score = URGENCY_KW.filter(w => textContent.includes(w)).length;
  features.brand_impersonation = BRANDS.filter(b => textContent.includes(b)).length;

  // ── Compute Baseline Score ────────
  let heuristicScore = 0;
  if (features.ip_as_url) heuristicScore += 25;
  if (features.link_mismatch > 0) heuristicScore += 20;
  if (features.shortened_url > 0) heuristicScore += 10;
  if (features.url_count > 5) heuristicScore += 5;
  heuristicScore += Math.min(features.urgency_score * 7, 21);
  heuristicScore += Math.min(features.brand_impersonation * 3, 9);
  if (features.has_form) heuristicScore += 8;
  if (features.has_password_input) heuristicScore += 7;
  heuristicScore = Math.min(Math.round(heuristicScore), 100);

  return {
    headers: mailObj.headers || "",
    sender: mailObj.sender || "",
    subject: mailObj.subject || "",
    clean_text: cleanTextForAI,
    urls: extractedUrls,
    heuristic_features: features,
    heuristic_score: heuristicScore
  };
}

module.exports = { extractData };