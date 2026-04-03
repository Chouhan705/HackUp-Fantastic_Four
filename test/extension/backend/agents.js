// agents.js
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });
const dns = require('dns').promises; // ⬅️ Native Node.js DNS module

// ==========================================
// 🛑 HACKATHON MASTER TOGGLE 🛑
// Set to 1 to enable Gemini AI. Set to 0 to bypass LLMs and save billing.
// ==========================================
const USE_AI_SWARM = 1; 

const { GoogleGenerativeAI } = require("@google/generative-ai");
const { extractData } = require('./extraction'); 

const genAI_1 = new GoogleGenerativeAI(process.env.GEMINI_API_KEY_1);
const genAI_2 = new GoogleGenerativeAI(process.env.GEMINI_API_KEY_2);

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
// 🌐 NETWORK INTELLIGENCE (The "spfpy" equivalent)
// ==========================================

function extractOriginIP(headers) {
    const match = headers.match(/Received: from .*?\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\].*?/i);
    return match ? match[1] : "Unknown IP";
}

async function fetchDomainSecurityRecords(domain) {
    let spf = "No SPF Record Found (FAIL)";
    let dmarc = "No DMARC Record Found (FAIL)";

    try {
        const records = await dns.resolveTxt(domain);
        const spfRecord = records.flat().find(r => r.startsWith('v=spf1'));
        if (spfRecord) spf = spfRecord;
    } catch (e) { /* Domain might not exist or no TXT records */ }

    try {
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
        const dmarcRecord = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));
        if (dmarcRecord) dmarc = dmarcRecord;
    } catch (e) { /* No DMARC configured */ }

    return { spf, dmarc };
}

// ==========================================
// AGENT 1: DNA DETECTIVE (Uses Key 1)
// ==========================================
async function runDnaAgent(headers, senderEmail) {
    const domainMatch = senderEmail.match(/@([\w.-]+)/);
    const domain = domainMatch ? domainMatch[1] : "";

    const originIP = extractOriginIP(headers);
    const hasDKIM = headers.toLowerCase().includes('dkim-signature:') ? "Present" : "Missing or Invalid";

    let securityRecords = { spf: "Unknown", dmarc: "Unknown" };
    if (domain) {
        securityRecords = await fetchDomainSecurityRecords(domain);
    }

    const prompt = `You are a Senior Mail Server Architect and Cyber-Forensics Expert. 
    Do NOT rely on Google's authentication headers. You must evaluate the raw data yourself.
    
    Email Claimed Sender: ${senderEmail}
    Sender Domain: ${domain}
    Origin IP Address: ${originIP}
    
    Live DNS Records (Fetched Real-Time):
    - SPF Record: "${securityRecords.spf}"
    - DMARC Record: "${securityRecords.dmarc}"
    - DKIM Signature in Headers: ${hasDKIM}
    
    Analyze if the Origin IP is permitted by the SPF record. Analyze if the DMARC policy (e.g., p=reject, p=none) indicates strict enforcement. 
    
    Output JSON format: {"is_spoofed": boolean, "auth_score": number, "technical_summary": "string"}`;
    
    return await runAgent(prompt, headers, genAI_1);
}

// ==========================================
// AGENT 2: LINK HUNTER (Uses Key 1)
// ==========================================
async function runLinkAgent(urls) {
    if (!urls || urls.length === 0) {
        return { malicious_urls: [], link_risk_score: 0, hunter_note: "No links detected in the email payload." };
    }

    const prompt = `You are a Cyber-Threat Intelligence specialist. Analyze these URLs for typosquatting and risks.
    Output JSON format: {"malicious_urls": ["string"], "link_risk_score": number, "hunter_note": "string"}`;
    
    return await runAgent(prompt, urls, genAI_1); 
}

// ==========================================
// AGENT 3: PROFILER (Uses Key 2)
// ==========================================
async function runProfilerAgent(body, fromAddress) {
    const systemPrompt = `You are an Expert in Social Engineering. Analyze this email text.
    CRITICAL IMPERSONATION CHECK: The email was actually sent by: "${fromAddress}". 
    Read the body text. Does the email claim to be from a completely different company, brand, or organization? 
    If they do not match, flag it as a HIGH RISK Impersonation attempt.
    
    Output JSON format: {"is_ai_generated": boolean, "manipulation_score": number, "profiler_summary": "string"}`;
    
    return await runAgent(systemPrompt, body, genAI_2); 
}

// ==========================================
// AGENT 4: THE JUDGE (Uses Key 2)
// ==========================================
async function runJudgeAgent(dnaReport, linkReport, profilerReport, heuristicScore) {
    const systemPrompt = `You are the Lead Forensic Judge for PhishGuard.AI. 
    Your job is to read the reports from your three specialist agents, ALONG WITH the hard heuristic risk score generated by the system's static analysis tool, and determine the final threat level.
    
    Output ONLY JSON format: 
    {
        "final_risk_score": number (0-100), 
        "threat_level": "Safe" | "Suspicious" | "Dangerous" | "Critical", 
        "user_friendly_summary": "A 2-sentence plain English explanation of why this email is dangerous, meant for a non-technical user.", 
        "key_evidence": ["string", "string", "string"] 
    }`;

    const caseFile = {
        hard_heuristic_score: heuristicScore,
        dna_evidence: dnaReport,
        link_evidence: linkReport,
        behavioral_evidence: profilerReport
    };

    return await runAgent(systemPrompt, caseFile, genAI_2); 
}

// ==========================================
// THE MASTER ORCHESTRATOR
// ==========================================

function getHeuristicThreatLevel(score) {
    if (score >= 70) return "Critical";
    if (score >= 40) return "Suspicious";
    if (score > 0) return "Suspicious"; 
    return "Safe";
}

async function processEmailAnalysis(rawMailObj) {
    console.log("⚙️ Running Heuristic Extraction...");
    const parsedData = extractData(rawMailObj);

    try {
        // 🛑 THE KILL SWITCH IN ACTION
        if (!USE_AI_SWARM) {
            throw new Error("Master Toggle is set to 0. Bypassing Gemini to save billing.");
        }

        console.log("🧠 Initiating Agentic Swarm (Independent DNS Validation)...");
        const [dnaReport, linkReport, profilerReport] = await Promise.all([
            runDnaAgent(parsedData.headers, parsedData.sender), 
            runLinkAgent(parsedData.urls),
            runProfilerAgent(parsedData.clean_text, parsedData.sender)
        ]);

        console.log("⚖️ The Judge is reviewing...");
        // ⬅️ CRITICAL FIX: Uncommented this line!
        const finalVerdict = await runJudgeAgent(dnaReport, linkReport, profilerReport, parsedData.heuristic_score);

        return {
            id: rawMailObj.id,           
            subject: rawMailObj.subject, 
            sender: rawMailObj.sender,   
            date: rawMailObj.date,       
            
            ...finalVerdict,
            heuristic_breakdown: parsedData.heuristic_features,
            is_fallback: false 
        };

    } catch (error) {
        console.error("⚠️ AI Swarm Offline, Bypassed, or Rate Limited! Using Heuristic Engine:", error.message);

        const fallbackThreat = getHeuristicThreatLevel(parsedData.heuristic_score);

        return {
            id: rawMailObj.id,           
            subject: rawMailObj.subject, 
            sender: rawMailObj.sender,   
            date: rawMailObj.date,       

            final_risk_score: parsedData.heuristic_score,
            threat_level: fallbackThreat,
            user_friendly_summary: "Live AI analysis is currently bypassed or unavailable. This risk score was generated using our offline static heuristic scanning engine.",
            key_evidence: [
                `Static Heuristic Score: ${parsedData.heuristic_score}/100`,
                parsedData.heuristic_features.has_password_input ? "Password input field detected." : "No password inputs detected.",
                `Suspicious links flagged: ${parsedData.heuristic_features.link_mismatch}`
            ],
            heuristic_breakdown: parsedData.heuristic_features,
            is_fallback: true 
        };
    }
}

module.exports = { processEmailAnalysis };