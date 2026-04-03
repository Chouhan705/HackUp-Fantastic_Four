const { localSentry } = require('./layers/layer1_sentry');
const { localProber } = require('./layers/layer2_prober');
const { gatherFacts } = require('./layers/layer3_facts');
const { runSpecializedAgents } = require('./layers/layer4_agents');
const { finalJudge } = require('./layers/layer5_judge');
const { maskPII } = require('./utils/pii-masker');

/**
 * 0. Handle Redirect Chains
 * Solves the blind-spot where attackers hide behind shorteners or marketing trackers.
 */
async function resolveRedirects(urls) {
  const TRACKING_DOMAINS = [
      'rs6.net', 'clicks.eventbrite.com', 't.co', 'mailchimp', 
      'customeriomail.com', 'mandrillapp.com', 'sendgrid.net',
      'eventbrite.com', 'hubspotlinks.com', 'hs-analytics.net', 'hubspotemail.net'
  ];

  const resolutionPromises = urls.map(async (url) => {
      if (!url.startsWith('http')) return url;
      
      try {
          const hostname = new URL(url).hostname;
          const isTracker = TRACKING_DOMAINS.some(d => hostname.includes(d));
          
          if (isTracker) {
              const controller = new AbortController();
              const timeoutId = setTimeout(() => controller.abort(), 6000); // HubSpot is notoriously slow, giving it 6 seconds
              // Use GET over HEAD since many email marketing trackers drop HEAD requests or refuse to redirect them
              let response = await fetch(url, { method: 'GET', redirect: 'follow', signal: controller.signal });
              
              const contentType = response.headers.get('content-type') || '';
              if (response.status === 200 && contentType.includes('text/html')) {
                  const html = await response.text();
                  const hubspotMatch = html.match(/href=["']([^"']+)_jss=0["'][^>]*>click here<\/a>/i);
                  if (hubspotMatch && hubspotMatch[1]) {
                      const innerUrl = hubspotMatch[1] + '_jss=0';
                      response = await fetch(innerUrl.replace(/&amp;/g, '&'), { method: 'GET', redirect: 'follow', signal: controller.signal });
                  }
              }
              
              clearTimeout(timeoutId);
              return response.url || url;
          }
          
          // If not a known tracking wrapper, do not waste time resolving
          return url;
      } catch (e) {
          return url;
      }
  });

  // Concurrently resolve all tracking links instead of waiting sequentially
  return await Promise.all(resolutionPromises);
}

/**
 * PhishGuard.AI - 5-Layer Waterfall Defense
 * Master Orchestrator
 * @param {Object} rawEmail - The incoming email object (headers, body, urls)
 * @returns {Promise<Object>} - Final Risk Assessment JSON
 */
async function analyzeEmail(rawEmail) {
  const startTime = Date.now();

  try {
    // 0. Input Sanitization & Normalization
    if (!rawEmail || typeof rawEmail !== 'object') throw new Error("Invalid email payload");
    rawEmail.headers = rawEmail.headers || {};
    rawEmail.body = rawEmail.body || "";
    rawEmail.urls = Array.isArray(rawEmail.urls) ? rawEmail.urls : [];

    // Filter out UI and Safe known noise domains
    const ignoreList = ['support.google.com', 'accounts.google.com', 'myaccount.google.com', 'mail.google.com'];
    rawEmail.urls = rawEmail.urls.filter(u => {
        try {
            const hostname = new URL(u).hostname.toLowerCase();
            return !ignoreList.some(ignore => hostname.endsWith(ignore));
        } catch(e) { return true; }
    });

    // Categorize Email Type
    const isMarketing = (rawEmail.urls.length >= 10);
    if (isMarketing) {
        console.log(`[Pipeline] Email classified as MARKETING (${rawEmail.urls.length} URLs). Reducing risk baseline.`);
    } else {
        console.log(`[Pipeline] Email classified as TRANSACTIONAL/PHISHING candidate (${rawEmail.urls.length} URLs).`);
    }

    // Determine priority links (e.g. limit to 3-5 to save latency and focus on CTAs)
    if (rawEmail.urls.length > 5) {
        rawEmail.urls = rawEmail.urls.slice(0, 5); // Simplistic top 5
    }

    // T3: Handle Redirect Chains (You are blind without this)
    if (rawEmail.urls.length > 0) {
        console.log(`[Pipeline] Resolving redirect chains for ${rawEmail.urls.length} prioritized URLs...`);
        rawEmail.urls = await resolveRedirects(rawEmail.urls);
    }

    // T1: Reordered Pipeline: Sentry -> Trust/Facts -> ML -> Judge

    // LAYER 1: The Sentry (Custom Regex & Heuristics)
    const localVerdict = localSentry(rawEmail);
    if (localVerdict.isCritical) {
      console.log(`[Layer 1: The Sentry] BLOCKED: ${localVerdict.reason}`);
      return formatFinalOutput(localVerdict);
    }

    // Mask PII before hitting Cloud/AI Layers
    const safeEmail = maskPII(rawEmail);

    // LAYER 2: Trust Engine & Fact Checkers (Deterministic APIs)
    const facts = await gatherFacts(safeEmail);

    // T2: TRUST ASSESSMENT
    const age = facts.whois?.domain_age_days;
    const isAuthPass = facts.mail_auth?.spf === "pass" && facts.mail_auth?.dkim === "pass" && facts.mail_auth?.dmarc === "pass";
    const isSafeBrowsing = facts.safe_browsing?.url_reputation === "clean";

    // Fix C: Implicit Trust List for .gov and .edu domains if WHOIS is unknown
    let isTrustedSender = (typeof age === 'number' && age > 1825 && isAuthPass && isSafeBrowsing);
    let senderDomain = null;
    
    if (safeEmail.headers && safeEmail.headers.from) {
        const fromHeader = safeEmail.headers.from;
        const emailRegex = /@([a-zA-Z0-9.-]+)/;
        const match = fromHeader.match(emailRegex);
        if (match) {
            senderDomain = match[1].toLowerCase().trim();
            if ((senderDomain.endsWith('.gov') || senderDomain.endsWith('.edu')) && isAuthPass) {
                isTrustedSender = true;
                if (!facts.whois) facts.whois = {};
                facts.whois.domain_age_days = 10000; // Implicit Authority
                console.log(`[Rule Engine] Applied Implicit Trust for ${senderDomain} (Auth Passed). Setting Age to 10000.`);
            }
        }
    }

    if (isTrustedSender) {
        console.log(`[Rule Engine] Sender is highly trusted. Adjusting base risk, but continuing analysis.`);
    }

    // T2: "Kill-Switch" & Context Match Rule Engine
    let contextMismatch = false;
    let mismatchDetails = null;
    let contextMatch = false;

    if (safeEmail.urls && safeEmail.urls.length > 0) {
        const finalUrl = safeEmail.urls[0];
        try {
            const urlObj = new URL(finalUrl);
            const linkHostname = urlObj.hostname.toLowerCase();
            const badInfra = ['ngrok.io', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'pagekite.me'];
            
            if (badInfra.some(infra => linkHostname.endsWith(infra))) {
                console.log(`[Rule Engine] CRITICAL OVERRIDE: High-risk staging infrastructure detected (${linkHostname}).`);
                return {
                    status: "BLOCKED",
                    score: 99,
                    logic_path: "Hard Rule -> High-Risk Infrastructure",
                    forensics: { reason: "Attackers commonly use this tunneling service.", evidence: [linkHostname] },
                    recommendation: "Never enter credentials on staging domains."
                };
            }

            // Context Match Check: Sender vs Link
            const GLOBAL_FOOTER_DOMAINS = [
                'google.com', 'google.co.in', 'about.google', 'youtube.com', // Google Workspace links
                'twitter.com', 'linkedin.com', 'facebook.com', // Social icons
                'constantcontact.com', 'rs6.net', 'eventbrite.com' // Trusted Marketing/Tracking
            ];

            if (senderDomain) {
                // Rule: If link is a global footer/social/tracking domain, it is NOT a mismatch.
                const isSafeMismatch = GLOBAL_FOOTER_DOMAINS.some(d => linkHostname.endsWith(d) || linkHostname === d);
                
                if (isSafeMismatch) {
                    console.log(`[Rule Engine] Safe Mismatch: Global footer/tracking domain allowed (${linkHostname}).`);
                } else if (!linkHostname.includes(senderDomain) && !senderDomain.includes(linkHostname)) {
                    contextMismatch = true;
                    mismatchDetails = `Sender domain (${senderDomain}) points to unrelated link (${linkHostname})`;
                } else {
                    contextMatch = true;
                }
            }
        } catch(e) {
            // Invalid URL, let it pass to ML/Sentry
        }
    }

    // Fix B: The Identity Rule
    if (contextMatch && isTrustedSender) {
        console.log(`[Rule Engine] DIRECT MATCH: Trusted sender domain matches resolved URL.`);
        return {
            status: "SAFE",
            score: 0,
            logic_path: "Identity Rule -> Trusted Entity matches Destination",
            forensics: { reason: "Sender identity perfectly matches the verified final link destination.", evidence: safeEmail.urls },
            recommendation: "Completely safe. Domain matches identity."
        };
    }

    if (isTrustedSender && contextMismatch) {
        console.log(`[Rule Engine] CRITICAL OVERRIDE: ${mismatchDetails}.`);
        return {
            status: "BLOCKED",
            score: 95,
            logic_path: "Context Mismatch -> Link does not match Trusted Sender",
            forensics: { reason: mismatchDetails, evidence: safeEmail.urls },
            recommendation: "The link destination has no relation to the sender's domain. High risk of phishing."
        };
    }

    // LAYER 3: The Prober (XGBoost ML)
    // Run ML ALWAYS, regardless of static trust
    const proberResult = await localProber(safeEmail);
    // Adjust prober threshold based on trust profile
    let blockThreshold = isTrustedSender ? 95 : 85;

    if (proberResult.isSuspicious && proberResult.riskScore >= blockThreshold) {
       console.log(`[Layer 3: The Prober] BLOCKED: ${proberResult.reason}`);
       return formatFinalOutput({ reason: proberResult.reason });
    }

    // Context aggregation
    const executionContext = {
      isTrustedSender: isTrustedSender,
      contextMismatch: contextMismatch,
      prober_score: proberResult,
      facts: facts,
      sentry_flags: localVerdict.flags || []
    };

    // LAYER 4: The Analysts (Gemini 2.0 Flash-Lite)
    const agentReports = await runSpecializedAgents(safeEmail, executionContext);

    // LAYER 5: The Judge (T5: The Scoring System)
    const finalVerdict = await finalJudge(safeEmail, executionContext, agentReports);

    const endTime = Date.now();
    console.log(`[Analysis Complete] Time taken: ${endTime - startTime}ms`);

    return finalVerdict;
  } catch (error) {
    console.error('[System Error] Waterfall Defense failed:', error);
    return fallbackResponse(error);
  }
}

function formatFinalOutput(localVerdict) {
  return {
    status: "BLOCKED",
    score: 100,
    logic_path: "Waterfall -> Sentry (Fail)",
    forensics: {
        trust_deficit: true,
        url_obfuscated: true,
        behavior_flags: [localVerdict.reason || "Suspicious Patterns detected"]
    },
    recommendation: "This email was blocked immediately by local security rules. Do not interact with it."
  };
}

function fallbackResponse(error) {
  return {
    status: "ERROR",
    score: -1,
    logic_path: "System Error",
    forensics: { error: error.message },
    recommendation: "Our systems encountered an error while scanning this email. Proceed with extreme caution."
  };
}

module.exports = { analyzeEmail };
