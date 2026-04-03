const { localSentry } = require('./layers/layer1_sentry');
const { localProber } = require('./layers/layer2_prober');
const { gatherFacts } = require('./layers/layer3_facts');
const { runSpecializedAgents } = require('./layers/layer4_agents');
const { finalJudge } = require('./layers/layer5_judge');
const { maskPII } = require('./utils/pii-masker');

/**
 * 0. Handle Redirect Chains
 * Solves the blind-spot where attackers hide behind shorteners.
 */
async function resolveRedirects(urls) {
  const resolved = [];
  for (const url of urls) {
      if (!url.startsWith('http')) {
          resolved.push(url);
          continue;
      }
      try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 1500);
          const response = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal });
          clearTimeout(timeoutId);
          resolved.push(response.url || url);
      } catch (e) {
          resolved.push(url);
      }
  }
  return resolved;
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

    // T3: Handle Redirect Chains (You are blind without this)
    if (rawEmail.urls.length > 0) {
        console.log(`[Pipeline] Resolving redirect chains for ${rawEmail.urls.length} URLs...`);
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

    // T2: HARD TRUST OVERRIDE
    // If Domain > 5 years, Auth = Pass, Browsing = clean -> Skip ML
    const age = facts.whois?.domain_age_days;
    const isAuthPass = facts.mail_auth?.spf === "pass" && facts.mail_auth?.dkim === "pass" && facts.mail_auth?.dmarc === "pass";
    const isSafeBrowsing = facts.safe_browsing?.url_reputation === "clean";

    if (typeof age === 'number' && age > 1825 && isAuthPass && isSafeBrowsing) {
        console.log(`[Rule Engine] HARD TRUST OVERRIDE: Verified sender > 5 years old. Skipping ML.`);
        return {
            status: "SAFE",
            score: 5,
            logic_path: "Hard Rule -> High-Trust Entity",
            forensics: { trust_deficit: false, url_obfuscated: false, behavior_flags: [] },
            recommendation: "This email originates from a highly trusted, verified sender."
        };
    }

    // T2: "Kill-Switch" Rule Engine
    if (safeEmail.urls && safeEmail.urls.length > 0) {
        const finalUrl = safeEmail.urls[0];
        try {
            const urlObj = new URL(finalUrl);
            const hostname = urlObj.hostname.toLowerCase();
            const badInfra = ['ngrok.io', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'pagekite.me'];
            
            if (badInfra.some(infra => hostname.endsWith(infra))) {
                console.log(`[Rule Engine] CRITICAL OVERRIDE: High-risk staging infrastructure detected (${hostname}).`);
                return {
                    status: "BLOCKED",
                    score: 99,
                    logic_path: "Hard Rule -> High-Risk Infrastructure",
                    forensics: { reason: "Attackers commonly use this tunneling service.", evidence: [hostname] },
                    recommendation: "Never enter credentials on staging domains."
                };
            }
        } catch(e) {
            // Invalid URL, let it pass to ML/Sentry
        }
    }

    // LAYER 3: The Prober (XGBoost ML)
    // Run ML ONLY if it wasn't statically trusted
    const proberResult = await localProber(safeEmail);
    if (proberResult.isSuspicious && proberResult.riskScore >= 85) {
       console.log(`[Layer 3: The Prober] BLOCKED: ${proberResult.reason}`);
       return formatFinalOutput({ reason: proberResult.reason });
    }

    // Context aggregation
    const executionContext = {
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
