const { localSentry } = require('./layers/layer1_sentry');
const { localProber } = require('./layers/layer2_prober');
const { gatherFacts } = require('./layers/layer3_facts');
const { runSpecializedAgents } = require('./layers/layer4_agents');
const { finalJudge } = require('./layers/layer5_judge');
const { maskPII } = require('./utils/pii-masker');

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

    // LAYER 1: The Sentry (Custom Regex & Heuristics)
    const localVerdict = localSentry(rawEmail);
    if (localVerdict.isCritical) {
      console.log(`[Layer 1: The Sentry] BLOCKED: ${localVerdict.reason}`);
      return formatFinalOutput(localVerdict);
    }

    // LAYER 2: The Prober (XGBoost via ONNX - Local ML)
    // Simulated lightweight local AI logic for structural anomalies
    const proberResult = await localProber(rawEmail);
    if (proberResult.isSuspicious && proberResult.riskScore >= 85) {
       console.log(`[Layer 2: The Prober] BLOCKED: ${proberResult.reason}`);
       return formatFinalOutput({ reason: proberResult.reason });
    }

    // Mask PII before hitting Cloud/AI Layers
    const safeEmail = maskPII(rawEmail);

    // LAYER 3: The Fact-Checkers (Deterministic APIs - WHOIS, Safe Browsing, VirusTotal)
    const facts = await gatherFacts(safeEmail);

    // Context aggregation
    const executionContext = {
      prober_score: proberResult,
      facts: facts
    };

    // LAYER 4: The Analysts (Gemini 2.0 Flash-Lite)
    // Runs Agent A (DNA), Agent B (Links), Agent C (Profiler)
    const agentReports = await runSpecializedAgents(safeEmail, executionContext);

    // LAYER 5: The Judge (Gemini 2.0 Flash)
    // Final Verdict & Q/A explanation based on Agent consensus and Deterministic Facts
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
    final_risk_score: 100,
    threat_level: "Critical",
    user_friendly_summary: "This email was blocked immediately by local security rules. Do not interact with it.",
    key_evidence: [localVerdict.reason],
    agent_reports: { dna: {}, links: {}, profiler: {} }
  };
}

function fallbackResponse(error) {
  return {
    final_risk_score: 50,
    threat_level: "Suspicious",
    user_friendly_summary: "Our systems encountered an error while scanning this email. Proceed with extreme caution.",
    key_evidence: ["System timeout or error during analysis."],
    agent_reports: { error: error.message }
  };
}

module.exports = { analyzeEmail };
