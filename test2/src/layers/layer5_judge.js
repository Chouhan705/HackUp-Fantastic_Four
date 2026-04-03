module.exports = {
  finalJudge: function finalJudge(email, executionContext, agentReports) {
    const facts = executionContext.facts || {};
    let overrideReason = null;

    // Rule 1: Safe Browsing Blacklist -> CRITICAL
    if (facts.safe_browsing && facts.safe_browsing.url_reputation === 'malicious') {
        return {
            status: 'BLOCKED',
            score: 100,
            logic_path: 'Hard Rule -> Blacklisted URL',
            forensics: { behavior_flags: ['URL found on reputable blacklist.'] },
            recommendation: 'DO NOT CLICK. A link in this email is known to distribute malware or phishing.'
        };
    }

    // Rule 2: Critical Rule Triggered from Contradiction Engine
    if (executionContext.criticalRuleTriggered) {
        return {
            status: 'BLOCKED',
            score: 100,
            logic_path: 'Hard Rule -> Critical Contradiction',
            forensics: { behavior_flags: [executionContext.contradictionReason || 'Critical contradiction found'] },
            recommendation: 'DO NOT CLICK. ' + (executionContext.contradictionReason || 'High risk of phishing.')
        };
    }

    // Rule 3: Suspicious Contradiction from Contradiction Engine
    if (executionContext.hasSuspiciousContradiction) {
         // Elevate base score because trusted sender is pointing to unknown infra
         return {
            status: 'WARNING',
            score: 85,
            logic_path: 'Hard Rule -> Suspicious Contradiction',
            forensics: { behavior_flags: [executionContext.contradictionReason || 'Suspicious routing from trusted sender', 'Agent Evaluation Required'] },
            recommendation: 'Proceed with extreme caution. The sender is verified, but the links lead to unexpected destinations.'
        };
    }

    // Scored evaluation (Fallback for ambiguous cases)
    let final_risk_score = 20;

    // URL score (ML Prober contribution is capped)
    if (executionContext.prober_score && executionContext.prober_score.riskScore) {
       final_risk_score += (executionContext.prober_score.riskScore * 0.3); // max ~ 30
    }

    // Sentry behavior flags
    let sentry_flags = executionContext.sentry_flags || [];
    if (sentry_flags.includes('obfuscation_detected')) final_risk_score += 15;
    if (sentry_flags.includes('high_urgency')) final_risk_score += 10;

    // Agent Risks
    const agentRisks = [
      (agentReports && agentReports.dna ? agentReports.dna.risk : 'unknown'),
      (agentReports && agentReports.links ? agentReports.links.risk : 'unknown'),
      (agentReports && agentReports.profiler ? agentReports.profiler.risk : 'unknown')
    ];
    
    const agentFlags = [];
    if (agentReports) {
        if (agentReports.dna && agentReports.dna.finding && agentReports.dna.risk !== 'low') {
            agentFlags.push(`[DNA Risk: ${agentReports.dna.risk.toUpperCase()}] ${agentReports.dna.finding}`);
        } else if (agentReports.dna && agentReports.dna.finding) {
            agentFlags.push(`DNA Agent: ${agentReports.dna.finding}`);
        }
        
        if (agentReports.links && agentReports.links.finding && agentReports.links.risk !== 'low') {
            agentFlags.push(`[Link Risk: ${agentReports.links.risk.toUpperCase()}] ${agentReports.links.finding}`);
        } else if (agentReports.links && agentReports.links.finding) {
            agentFlags.push(`Link Agent: ${agentReports.links.finding}`);
        }
        
        if (agentReports.profiler && agentReports.profiler.finding && agentReports.profiler.risk !== 'low') {
            agentFlags.push(`[Profiler Risk: ${agentReports.profiler.risk.toUpperCase()}] ${agentReports.profiler.finding}`);
        } else if (agentReports.profiler && agentReports.profiler.finding) {
            agentFlags.push(`Profiler Agent: ${agentReports.profiler.finding}`);
        }
    }
    
    // Add up to 30 points for Agent warnings
    let agent_score = agentRisks.filter(r => r === 'high' || r === 'critical').length * 10;
    if (agent_score > 30) agent_score = 30;
    final_risk_score += agent_score;

    if (final_risk_score > 100) final_risk_score = 100;
    
    let status = final_risk_score >= 80 ? 'BLOCKED' : (final_risk_score >= 40 ? 'WARNING' : 'SAFE');
    
    let recommendation = `Engine assessed score ${Math.round(final_risk_score)}.`;
    if (status === 'SAFE') recommendation = "Content appears safe and exhibits no known malicious signatures.";
    else if (status === 'WARNING') recommendation = "Exercise caution. Some anomalous or suspicious patterns were detected.";
    else if (status === 'BLOCKED') recommendation = "High risk of phishing or malicious activity. Do not interact.";

    let proberScore = 0;
    if (executionContext.prober_score && executionContext.prober_score.riskScore) {
        proberScore = Math.round(executionContext.prober_score.riskScore);
    }
    
    return {
        status: status,
        score: Math.round(final_risk_score),
        logic_path: `Hybrid Pipeline \n↓\n Sentry Rules \n↓\n ML Prober (Risk: ${proberScore}%) \n↓\n 3-Agent Analysis \n↓\n Judge Consensus: ${status}`,
        forensics: {
            behavior_flags: [...sentry_flags, ...agentFlags]
        },
        recommendation: recommendation
    };
  }
};

