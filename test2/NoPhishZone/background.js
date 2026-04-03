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
export async function checkPopularity(url) {
  await loadBloomFilter();
  if (!popularDomainsFilter) return false;
  
  try {
    const rootDomain = new URL(url).hostname.replace(/^www\./, '').toLowerCase();
    
    for (let i = 0; i < popularDomainsFilter.k; i++) {
        // Assume `murmurhash3` is an imported library: 
        // const digest = murmurhash3.x86.hash32(rootDomain, i);
        // (For testing purposes, we use a mock digest if not bundled)
        const mockDigest = Math.abs(hashCode(rootDomain + i)); 
        const digest = mockDigest; // REPLACE with murmurhash3 logic
        
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

// Simple JS string hash (if not using murmurhash3 library)
function hashCode(str) {
    let hash = 0;
    for (let i = 0, len = str.length; i < len; i++) {
        let chr = str.charCodeAt(i);
        hash = (hash << 5) - hash + chr;
        hash |= 0;
    }
    return hash;
}

// Extract the 8 features, including our new `is_popular_domain`
export async function extractFeatures(url) {
  const urlObj = new URL(url);
  const url_length = url.length;
  const dot_count = (url.match(/\./g) || []).length;
  const has_https = url.startsWith('https://') ? 1 : 0;
  const is_ip_address = /^https?:\/\/\d+\.\d+\.\d+\.\d+/.test(url) ? 1 : 0;
  
  const digit_ratio = (url.match(/\d/g) || []).length / url_length;
  const special_char_count = (url.match(/[^\w\s\.]/g) || []).length;
  
  // Dummy domain age, replaced by real Whois API later if needed
  const domain_age_days = 2000; 

  const isPopular = await checkPopularity(url);
  const is_popular_domain = isPopular ? 1 : 0;

  return [
    url_length, 
    dot_count, 
    has_https, 
    is_ip_address, 
    digit_ratio, 
    special_char_count, 
    domain_age_days, 
    is_popular_domain
  ];
}

// Emulating the refined waterfall logic 
export async function analyzeUrl(url, xgboostScore) {
  const isPopular = await checkPopularity(url);
  
  if (xgboostScore > 0.9) {
    if (!isPopular) {
      return "CRITICAL: Phishing Detected!";
    } else {
      // Escalation! Domain is extremely popular but model scored it highly dangerous.
      // E.g., GitHub Pages, AWS S3 abuse.
      return "ESCALATE_TO_GEMINI_FLASH_LITE";
    }
  }
  
  return "SAFE";
}
