// agents.js
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const dns = require('dns').promises; 

// ==========================================
// 🛑 MASTER TOGGLE FOR GEMINI AI 🛑
// Set to 1 to enable Gemini AI. Set to 0 to bypass LLMs.
// ==========================================
const USE_AI_SWARM = 1; 

const { GoogleGenerativeAI } = require("@google/generative-ai");
const { extractData } = require('./extraction'); 

const genAI_1 = new GoogleGenerativeAI(process.env.GEMINI_API_KEY_1);
const genAI_2 = new GoogleGenerativeAI(process.env.GEMINI_API_KEY_2);

// ==========================================
// 🌐 NETWORK & DNS HELPERS
// ==========================================

function extractOriginIP(headers) {
    // FIX: Match ALL IPs in the routing chain and grab the last one (the true origin)
    const matches = [...headers.matchAll(/Received: from .*?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].*?/gi)];
    return matches.length > 0 ? matches[matches.length - 1][1] : "Unknown IP";
}

async function fetchDomainSecurityRecords(domain) {
    let spf = "No SPF Record Found (FAIL)";
    let dmarc = "No DMARC Record Found (FAIL)";
    if (!domain) return { spf, dmarc };

    try {
        const records = await dns.resolveTxt(domain);
        const spfRecord = records.flat().find(r => r.startsWith('v=spf1'));
        if (spfRecord) spf = spfRecord;
    } catch (e) { /* ignore */ }

    try {
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
        const dmarcRecord = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));
        if (dmarcRecord) dmarc = dmarcRecord;
    } catch (e) { /* ignore */ }

    return { spf, dmarc };
}

// ==========================================
// 🛠️ LOCAL HEURISTIC ENGINE (Smarter Logic)
// ==========================================

function getHeuristicThreatLevel(score) {
    if (score >= 80) return "Critical";
    if (score >= 50) return "Dangerous";
    if (score >= 25) return "Untrusted"; 
    if (score > 0) return "Suspicious"; 
    return "Safe";
}

function calculateLocalHeuristicScore(parsedData, securityRecords, rawHeaders) {
    let score = 0;
    const evidence = [];
    const features = parsedData.heuristic_features || {};
    
    const body = (parsedData.clean_text || "").toLowerCase();
    const isFreemail = parsedData.is_freemail;

    // --- 1. DECEPTIVE LINKS & BRANDING ---
    if (features.deceptive_link > 0) { 
        score += 75; 
        evidence.push("CRITICAL: Deceptive Link detected (Text explicitly lies about destination)."); 
    }
    if (features.brand_impersonation > 0) { 
        score += 65; 
        evidence.push("CRITICAL: Impersonation attempt (Trusted name used with unverified sender)."); 
    }
    if (features.untrusted_link > 0 && features.deceptive_link === 0) {
        score += 25;
        evidence.push("UNTRUSTED: Link points to an unfamiliar or unverified domain.");
    }

    // --- 2. SENDER CONTEXT GAP (Fixed False Positive) ---
    // Swapped broad words for highly specific phishing phrases
    const bizPhrases = ["account suspended", "unauthorized login", "verify your identity", "payment declined", "invoice attached", "security alert"];
    const hasBizContext = bizPhrases.some(k => body.includes(k) || parsedData.subject.toLowerCase().includes(k));
    
    if (isFreemail && hasBizContext) { 
        score += 45; 
        evidence.push("HIGH RISK: Urgent transactional request sent from a personal freemail account."); 
    }

    // --- 3. TECHNICAL DNS FAILURES (Context-Aware) ---
    const dmarc = (securityRecords.dmarc || "").toLowerCase();
    const spf = (securityRecords.spf || "").toLowerCase();
    const hasDKIM = rawHeaders.toLowerCase().includes('dkim-signature:');

    // Only punish heavily if they are acting like a business or brand
    if (features.brand_impersonation > 0 || hasBizContext) {
        if (dmarc.includes("fail")) { score += 40; evidence.push("HIGH RISK: Impersonator failed DMARC."); }
        if (spf.includes("fail")) { score += 25; evidence.push("HIGH RISK: Impersonator failed SPF."); }
        if (!hasDKIM) { score += 15; evidence.push("Suspicious: Missing DKIM signature for business mail."); }
    } else {
        // Just a regular email failing DNS (Small business IT issue)
        if (dmarc.includes("fail")) { score += 10; evidence.push("Notice: Domain lacks valid DMARC."); }
        if (spf.includes("fail")) { score += 5; evidence.push("Notice: SPF authentication failed."); }
    }

    // --- 4. MALICIOUS PAYLOADS (Split Logic) ---
    if (features.ip_as_url > 0) { score += 55; evidence.push("CRITICAL: Link uses raw IP address instead of domain."); }
    
    if (parsedData.attachments?.length > 0) {
        const hasLethal = parsedData.attachments.some(f => /\.(exe|vbs|bat|ps1|scr)$/i.test(f.name));
        const hasSuspicious = parsedData.attachments.some(f => /\.(zip|rar|html|htm|pdf|docm)$/i.test(f.name));

        if (hasLethal) { 
            score += 85; 
            evidence.push("CRITICAL: Highly dangerous executable attachment detected."); 
        } else if (hasSuspicious) { 
            score += 15; 
            evidence.push("Caution: Email contains archived or document attachments."); 
        }
    }

    // --- 5. CONTENT URGENCY ---
    if (features.urgency_score > 0) {
        const weight = Math.min(features.urgency_score * 10, 30);
        score += weight;
        evidence.push("URGENCY: Psychological pressure or high-urgency language detected.");
    }

    // --- FINAL AGGREGATION ---
    let finalScore = Math.max(0, score); // Removed the flawless DNS safety bonus

    // STRICT OVERRIDES
    if ((features.deceptive_link > 0 || features.brand_impersonation > 0) && finalScore < 85) {
        finalScore = 88;
    }

    return { 
        score: Math.min(finalScore, 100), 
        evidence: [...new Set(evidence)] 
    };
}

// ==========================================
// 🧠 AGENTIC SWARM (Gemini 2.5 Flash)
// ==========================================

async function runAgent(systemPrompt, inputData, aiInstance) {
    const model = aiInstance.getGenerativeModel({ 
        model: "gemini-2.5-flash",
        systemInstruction: systemPrompt,
        generationConfig: { responseMimeType: "application/json" }
    });

    const prompt = typeof inputData === 'string' ? inputData : JSON.stringify(inputData);
    const result = await model.generateContent(prompt);
    return JSON.parse(result.response.text());
}

// ==========================================
// 🔍 DNA AGENT (Gemini 2.5 Flash)
// ==========================================
async function runDnaAgent(headers, senderEmail, securityRecords) {
    const originIP = extractOriginIP(headers);
    const hasDKIM = headers.toLowerCase().includes('dkim-signature:') ? "Present" : "Missing or Invalid";

    const systemPrompt = `You are a Cyber-Forensics Expert. Evaluate email technical authenticity. Be concise.
        Output JSON: {"is_spoofed": boolean, "auth_score": number, "technical_summary": "1 sentence max."}`;

    return await runAgent(systemPrompt, { senderEmail, originIP, securityRecords, hasDKIM }, genAI_1);
}

// ==========================================
// 🔍 LINK HUNTER AGENT (Gemini 2.5 Flash)
// ==========================================
async function runLinkAgent(urls) {
    if (!urls || urls.length === 0) return { malicious_urls: [], link_risk_score: 0, hunter_note: "No links detected." };
    const systemPrompt = `You are a Threat Intelligence Analyst. Flag deceptive URLs, homograph attacks, malicious redirects. Be concise.
        Output JSON: {"malicious_urls": ["string"], "link_risk_score": number, "hunter_note": "1 sentence max."}`;
    return await runAgent(systemPrompt, urls, genAI_1);
}

// ==========================================
// 🔍 PROFILER AGENT (Gemini 2.5 Flash)
// ==========================================
async function runProfilerAgent(body, fromAddress) {
    const systemPrompt = `You are a Social Engineering Expert. Detect brand impersonation and psychological manipulation. Be concise.
        Output JSON: {"is_ai_generated": boolean, "manipulation_score": number, "profiler_summary": "1 sentence max."}`;
    return await runAgent(systemPrompt, { fromAddress, body }, genAI_2);
}

// ==========================================
// AGENT 4: THE JUDGE (Uses Key 2)
// ==========================================
async function runJudgeAgent(dnaReport, linkReport, profilerReport, heuristicScore) {
    const systemPrompt = `You are the Lead Forensic Judge for PhishGuard.AI. Synthesize the data below into a final verdict. Be concise.

        INPUT:
        - Heuristic Score: ${heuristicScore}
        - DNA Report: ${JSON.stringify(dnaReport)}
        - Link Report: ${JSON.stringify(linkReport)}
        - Profiler Report: ${JSON.stringify(profilerReport)}

        RULES:
        1. MISCONFIGURED MARKETING: If spoofed but content is benign (newsletter, no deceptive links) → score 35-49, level "Untrusted". State it appears to be a misconfigured marketing sender.
        2. MALICIOUS SPOOF: If spoofed + high-pressure tactics or deceptive links → escalate to "Critical" (>85).

        Output ONLY JSON:
        {
            "final_risk_score": number (0-100),
            "threat_level": "Safe" | "Suspicious" | "Untrusted" | "Dangerous" | "Critical",
            "user_friendly_summary": "1-2 sentences max.",
            "key_evidence": ["3 bullet points, 10 words each max"]
        }`;

    const caseFile = {
        local_heuristic_score: heuristicScore,
        ai_dna_validation: dnaReport,
        ai_link_validation: linkReport,
        ai_behavioral_validation: profilerReport
    };

    return await runAgent(systemPrompt, caseFile, genAI_2);
}

// ==========================================
// 🚀 THE MASTER ORCHESTRATOR
// ==========================================

async function processEmailAnalysis(rawMailObj) {
    console.log("⚙️ Extracting Data...");
    const parsedData = extractData(rawMailObj);
    
    const domainMatch = parsedData.sender.match(/@([\w.-]+)/);
    const domain = domainMatch ? domainMatch[1] : "";
    const securityRecords = await fetchDomainSecurityRecords(domain);

    // FIX: Passed raw headers into the calculator for the DKIM check
    const heuristicResults = calculateLocalHeuristicScore(parsedData, securityRecords, parsedData.headers);
    console.log(`📊 Local Heuristic Score: ${heuristicResults.score}`);

    // --- 🛑 STRICT TOGGLE CHECK ---
    // Only run AI if Toggle is ON OR if score is in "Gray Area" (e.g., 20-75)
    const isGrayArea = heuristicResults.score >= 20 && heuristicResults.score <= 75;

    if (!USE_AI_SWARM && !isGrayArea) {
        return {
            ...rawMailObj,
            final_risk_score: heuristicResults.score,
            threat_level: getHeuristicThreatLevel(heuristicResults.score),
            user_friendly_summary: "(Static Engine) " + (heuristicResults.evidence[0] || "No critical threats detected via static scan."),
            key_evidence: heuristicResults.evidence,
            is_fallback: true 
        };
    }

    // --- 🧠 AI VALIDATION PHASE ---
    try {
        console.log(`🧠 AI Swarm Triggered (Score: ${heuristicResults.score})...`);
        const [dnaReport, linkReport, profilerReport] = await Promise.all([
            runDnaAgent(parsedData.headers, parsedData.sender, securityRecords), 
            runLinkAgent(parsedData.urls),
            runProfilerAgent(parsedData.clean_text, parsedData.sender)
        ]);

        const finalVerdict = await runJudgeAgent(dnaReport, linkReport, profilerReport, heuristicResults.score);

        return {
            ...rawMailObj, 
            ...finalVerdict,
            is_fallback: false 
        };

    } catch (error) {
        console.error("⚠️ AI Swarm Offline: Falling back to Heuristics.", error.message);
        return {
            ...rawMailObj,
            final_risk_score: heuristicResults.score,
            threat_level: getHeuristicThreatLevel(heuristicResults.score),
            user_friendly_summary: "Real-time AI analysis is currently unavailable. Displaying static heuristic results.",
            key_evidence: heuristicResults.evidence,
            is_fallback: true
        };
    }
}

module.exports = { processEmailAnalysis };