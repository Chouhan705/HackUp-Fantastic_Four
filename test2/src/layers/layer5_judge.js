/**
 * Layer 5: The Judge (Gemini 2.0 Flash)
 * Final Verdict: Aggregates all reports, resolves conflicts between agents, and writes the user-friendly explanation.
 */

// Hard Facts > AI Intuition: If a URL is on a blacklist or a domain is < 24 hours old, the risk is CRITICAL.
// Consensus: If two agents flag an email but one doesn't, the Judge must explain the discrepancy.

const { GoogleGenerativeAI } = require('@google/generative-ai');

async function finalJudge(email, executionContext, agentReports) {
  const { facts, prober_score } = executionContext;
  console.log(`[Layer 5: The Judge] The Final Judge is reviewing evidence...`);
  
  // 1. Hard Facts Override
  let criticalOverride = false;
  let overrideReason = "";

  if (facts.whois && facts.whois.domain_age_days < 1 && facts.whois.domain_age_days !== "Unknown") {
    criticalOverride = true;
    overrideReason = `The sender domain is less than 24 hours old. Highly suspicious.`;
  }
  
  if (facts.safe_browsing && facts.safe_browsing.url_reputation === "malicious") {
    criticalOverride = true;
    overrideReason += ` URL found on known blacklist.`;
  }

  // 2. Aggregate Agent Results
  // Safely extract risk levels, defaulting to "unknown" if an agent failed
  const dnaRisk = agentReports?.dna?.risk || "unknown";
  const linksRisk = agentReports?.links?.risk || "unknown";
  const profilerRisk = agentReports?.profiler?.risk || "unknown";

  const riskLevels = [dnaRisk, linksRisk, profilerRisk];
  const flagCount = riskLevels.filter(r => r === "high" || r === "critical").length;
  
  let discrepancySummary = null;
  if (flagCount === 2 && riskLevels.includes("low")) {
      discrepancySummary = "Discrepancy: Two agents flagged severe risks, but one reported low risk. Overriding to Suspicious based on majority.";
  }

  // Final Output Construction Schema
  // This simulates the structured output that Gemini 2.0 Flash would be forced to return via constraint formatting.
  const finalVerdict = {
      final_risk_score: criticalOverride ? 95 : (flagCount * 30 + 10),
      threat_level: criticalOverride ? "Critical" : (flagCount > 1 ? "Dangerous" : "Safe"),
      user_friendly_summary: criticalOverride ? `DO NOT CLICK. ${overrideReason}` : `This email appears ${flagCount > 0 ? "suspicious" : "safe"}. Please verify the sender.`,
      key_evidence: [
          overrideReason || null,
          agentReports?.dna?.finding || "DNA checks unavailable.",
          agentReports?.links?.finding || "Link checks unavailable.",
          agentReports?.profiler?.finding || "Behavioral checks unavailable."
      ].filter(Boolean),
      agent_reports: agentReports,
      notes: discrepancySummary
  };
  
  return finalVerdict;
}

module.exports = { finalJudge };
