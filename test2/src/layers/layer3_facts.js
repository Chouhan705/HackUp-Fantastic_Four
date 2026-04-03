/**
 * Layer 3: The Fact-Checkers (Deterministic APIs)
 * Goal: Ground Truth via WHOIS, Google Safe Browsing, VirusTotal
 */

// Simulated API Calls for Hackathon Demo

const checkWhois = async (domain) => {
  try {
    const apiKey = process.env.WHOIS_API_KEY;
    if (!apiKey || apiKey.includes("your_whois_api_key_here")) {
      console.warn("[Layer 3: WHOIS] API key missing, using fallback.");
      return { domain_age_days: domain.includes("evil") ? 0 : 365, status: "Simulated_Success" };
    }

    // Use a strict 1500ms timeout for external API calls to maintain the <2s constraint.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);

    const response = await fetch(
      `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`,
      { signal: controller.signal }
    );
    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const data = await response.json();
    
    if (data.WhoisRecord && data.WhoisRecord.createdDate) {
      const createdDate = new Date(data.WhoisRecord.createdDate);
      const diffTime = Date.now() - createdDate.getTime();
      const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
      return { domain_age_days: diffDays >= 0 ? diffDays : 0, status: "Success", raw_date: data.WhoisRecord.createdDate };
    }

    return { domain_age_days: "Unknown", status: "Missing_CreatedDate" };
  } catch (error) {
    console.error(`[Layer 3: WHOIS] API Error:`, error.message);
    return { domain_age_days: "Unknown", error: error.message };
  }
};

const checkSafeBrowsing = async (url) => {
  return new Promise((resolve) => setTimeout(() => {
    // Queries Google Safe Browsing / VirusTotal
    resolve({ url_reputation: url.includes("phish") ? "malicious" : "clean", status: "Success" });
  }, 150));
};

const checkMailAuth = async (headers) => {
  return new Promise((resolve) => setTimeout(() => {
    // Parses SPF, DKIM, DMARC
    const isSuspicious = headers.from && headers.from.includes("spoof");
    resolve({ 
      spf: isSuspicious ? "fail" : "pass", 
      dkim: "pass", 
      dmarc: isSuspicious ? "fail" : "pass", 
      status: "Success" 
    });
  }, 50));
};

async function gatherFacts(email) {
  const primaryDomain = extractDomain(email.headers.from);
  const primaryUrl = email.urls[0] || ""; // Pick first URL for demo simplicity

  console.log(`[Layer 3: The Fact-Checkers] Gathering facts for Domain: ${primaryDomain}, URL: ${primaryUrl}`);

  // Fetch all parallel API Data and gracefully handle errors
  const [whoisData, reputationData, authData] = await Promise.all([
    checkWhois(primaryDomain).catch(e => ({ domain_age_days: "Unknown", error: e.message })),
    checkSafeBrowsing(primaryUrl).catch(e => ({ url_reputation: "Unknown", error: e.message })),
    checkMailAuth(email.headers).catch(e => ({ spf: "Unknown", dkim: "Unknown", dmarc: "Unknown", error: e.message }))
  ]);

  const factSheet = {
    whois: whoisData,
    safe_browsing: reputationData,
    mail_auth: authData,
    timestamp: new Date().toISOString()
  };

  console.log(`[Layer 3: The Fact-Checkers] Fact sheet gathered:`, JSON.stringify(factSheet));
  return factSheet;
}

function extractDomain(addr) {
    if (!addr) return "unknown.com";
    return (addr.match(/@([\w.-]+)/) || [])[1] || "unknown.com";
}

module.exports = { gatherFacts };
