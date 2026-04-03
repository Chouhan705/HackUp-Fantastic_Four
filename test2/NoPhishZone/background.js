import { BloomFilter } from 'bloom-filters'; // Assumes you use a bundler (Webpack/Rollup)

chrome.runtime.onInstalled.addListener(() => {
  console.log("NoPhishZone Extension Installed");
});

// Load the Bloom filter from the shipped JSON file
let popularDomainsFilter = null;

async function loadBloomFilter() {
  if (popularDomainsFilter) return;
  try {
    const url = chrome.runtime.getURL('bloom.json');
    const response = await fetch(url);
    const data = await response.json();
    
    // We recreate our lightweight check since we packed bits into INTs in Python
    // (This is a custom rehydration, compatible with the Python mmh3 generation!)
    popularDomainsFilter = {
      m: data.m,
      k: data.k,
      data: data.data,
      // Lightweight murmurhash3 JS implementation or standard library should be used here.
      // For this example, assuming a global or imported murmurhash3 function:
      // import murmurhash3 from 'murmurhash3js';
    };
    console.log("Bloom Filter loaded successfully!", popularDomainsFilter);
  } catch (err) {
    console.error("Failed to load Bloom Filter:", err);
  }
}

// Hash logic manually aligned with python's `mmh3.hash(..., signed=False)`
// We would use `murmurhash3.x86.hash32(domain, seed)` in reality.
// We provide a stub for checkPopularity here.
export async function checkPopularity(domain) {
  await loadBloomFilter();
  if (!popularDomainsFilter) return false;
  
  try {
    const rootDomain = domain.replace(/^www\./, '').toLowerCase();
    
    for (let i = 0; i < popularDomainsFilter.k; i++) {
        const digest = murmurhash3_32_gc(rootDomain, i);

        const bitIndex = digest % popularDomainsFilter.m;
        const arrayIndex = Math.floor(bitIndex / 32);
        const bitOffset = bitIndex % 32;

        if ((popularDomainsFilter.data[arrayIndex] & (1 << bitOffset)) === 0) { 
            return false; // Definitely not popular
        }
    }
    return true; // Probably popular
  } catch(e) {
    return false;
  }
}

// Pure JS MurmurHash3 to perfectly match Python mmh3 logic
function murmurhash3_32_gc(key, seed) {
  var remainder, bytes, h1, h1b, c1, c2, k1, i;
  remainder = key.length & 3; // key.length % 4
  bytes = key.length - remainder;
  h1 = seed;
  c1 = 0xcc9e2d51;
  c2 = 0x1b873593;
  i = 0;
  while (i < bytes) {
    k1 = ((key.charCodeAt(i) & 0xff)) | ((key.charCodeAt(++i) & 0xff) << 8) | ((key.charCodeAt(++i) & 0xff) << 16) | ((key.charCodeAt(++i) & 0xff) << 24);
    ++i;
    k1 = ((((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16))) & 0xffffffff;
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = ((((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16))) & 0xffffffff;
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1b = ((((h1 & 0xffff) * 5) + ((((h1 >>> 16) * 5) & 0xffff) << 16))) & 0xffffffff;
    h1 = (((h1b & 0xffff) + 0x6b64) + ((((h1b >>> 16) + 0xe654) & 0xffff) << 16));
  }
  k1 = 0;
  switch (remainder) {
    case 3: k1 ^= (key.charCodeAt(i + 2) & 0xff) << 16;
    case 2: k1 ^= (key.charCodeAt(i + 1) & 0xff) << 8;
    case 1: k1 ^= (key.charCodeAt(i) & 0xff);
    k1 = (((k1 & 0xffff) * c1) + ((((k1 >>> 16) * c1) & 0xffff) << 16)) & 0xffffffff;
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = (((k1 & 0xffff) * c2) + ((((k1 >>> 16) * c2) & 0xffff) << 16)) & 0xffffffff;
    h1 ^= k1;
  }
  h1 ^= key.length;
  h1 ^= h1 >>> 16;
  h1 = (((h1 & 0xffff) * 0x85ebca6b) + ((((h1 >>> 16) * 0x85ebca6b) & 0xffff) << 16)) & 0xffffffff;
  h1 ^= h1 >>> 13;
  h1 = ((((h1 & 0xffff) * 0xc2b2ae35) + ((((h1 >>> 16) * 0xc2b2ae35) & 0xffff) << 16))) & 0xffffffff;
  h1 ^= h1 >>> 16;
  return h1 >>> 0;
export async function extractFeatures(url) {
  const urlObj = new URL(url);
  const hostname = urlObj.hostname;
  const rootDomain = getRootDomain(hostname);
  const url_length = url.length;
  const dot_count = (url.match(/\./g) || []).length;
  const has_https = url.startsWith('https://') ? 1 : 0;
  const is_ip_address = /^https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url) ? 1 : 0;
  
  const digit_ratio = (url.match(/\d/g) || []).length / url_length;
  const special_char_count = (url.match(/[^\w\s\.]/g) || []).length;
  
  // Dummy domain age, replaced by real Whois API later if needed
  const domain_age_days = 2000; 

  const isPopular = await checkPopularity(rootDomain);
  const is_popular_domain = isPopular ? 1 : 0;

  let infra_risk_score = 0.0;
  const hostnameLower = hostname.toLowerCase();
  if (hostnameLower.endsWith('.tk') || hostnameLower.endsWith('.ml') || hostnameLower.includes('10minutemail') || hostnameLower.includes('tempmail')) {
    infra_risk_score = 1.0;
  } else if (hostnameLower.includes('herokuapp.com') || hostnameLower.includes('vercel.app') || hostnameLower.includes('firebaseapp.com') || hostnameLower.includes('web.app')) {
    infra_risk_score = 0.7;
  }

  const features = [
    url_length,
    dot_count,
    has_https,
    is_ip_address,
    digit_ratio,
    special_char_count, 
    domain_age_days, 
    is_popular_domain,
    infra_risk_score

// Emulating the refined waterfall logic 
export async function analyzeUrl(url, xgboostScore) {
  const isPopular = await checkPopularity(url);
  
  // Dummy retrieval for Facts in Extension script context.
  const facts = {
      whois: { domain_age_days: 2000 },
      mail_auth: { spf: 'pass', dkim: 'pass' },
      safe_browsing: { url_reputation: 'clean' } 
  };

  const isOld = facts?.whois?.domain_age_days > 1825; // 5 Years
  const isAuth = facts?.mail_auth?.spf === 'pass' && facts?.mail_auth?.dkim === 'pass';
  const isClean = facts?.safe_browsing?.url_reputation === 'clean';
  
  if (isOld && isAuth && isClean) {
    return "SAFE_OVERRIDE";
  }
    if (isPopular) {
      // ESCALATE: Don't block, let the AI Judge handle it.
      console.log("[NoPhishZone] Complex URL on Trusted Domain. Escalating to Gemini...");
      return "ESCALATE_TO_GEMINI_JUDGE";
    } else {
      // BLOCK: Unknown domain + weird structure = Danger.
      return "CRITICAL: Phishing Detected!";
    }
  }
  
  return "SAFE";
}
