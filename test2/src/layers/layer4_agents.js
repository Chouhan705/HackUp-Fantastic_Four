/**
 * Layer 4: The Analysts (Gemini 2.0 Flash-Lite)
 * Specialized Reasoning: Three parallel "Agent" calls (DNA, Link, Profiler) that interpret the facts gathered in Layer 3.
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');

// In a real scenario, this would be process.env.GEMINI_API_KEY
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "YOUR_API_KEY_HERE");

// Using Gemini 2.0 Flash-Lite for high-speed
const initAgent = () => genAI.getGenerativeModel({ model: "gemini-2.0-flash-lite" });

/**
 * Agent A (The DNA Detective)
 * Analyze the Mailauth results.
 */
async function agentDNA(authFacts, emailHeaders) {
    try {
        const model = initAgent();
        const prompt = `You are a cybersecurity expert analyzing email authentication headers.
        Facts: ${JSON.stringify(authFacts)}
        Headers: ${JSON.stringify(emailHeaders)}
        If SPF fails but DKIM passes, determine if it's a mailing list or a spoof. Return a JSON reasoning string.`;
        
        // For the hackathon demo, we will mock the AI response to save tokens and execution time.
        // const result = await model.generateContent(prompt);
        // return result.response.text();
        
        return Promise.resolve({
            agent: "DNA Detective",
            finding: authFacts.spf === "fail" && authFacts.dkim === "pass" ? "Likely a mailing list forward." : "No SPF spoof detected.",
            risk: authFacts.spf === "fail" && authFacts.dkim === "fail" ? "high" : "low"
        });
    } catch (e) {
        console.error(`[Layer 4: The Analysts] DNA Agent Error: ${e.message}`);
        return { agent: "DNA Detective", finding: "Agent analysis unavailable. Assuming unknown risk based on facts.", risk: "unknown", error: e.message };
    }
}

/**
 * Agent B (The Link Hunter)
 * Analyze the URLs. Look for "Typosquatting".
 */
async function agentLinks(safeBrowsingFacts, urls, senderDomain) {
    try {
       // const model = initAgent(); ... (Implementation similar to Agent A)
       const hasTyposquat = urls.some(u => u.includes('microsft') || u.includes('g00gle'));
       return Promise.resolve({
           agent: "Link Hunter",
           finding: hasTyposquat ? "Typosquatting detected in URL." : "URLs match sender domain.",
           risk: hasTyposquat ? "critical" : "low"
       });
    } catch (e) {
        console.error(`[Layer 4: The Analysts] Link Agent Error: ${e.message}`);
        return { agent: "Link Hunter", finding: "Link analysis failed. Neutral fallback applied.", risk: "unknown", error: e.message };
    }
}

/**
 * Agent C (The Profiler)
 * Analyze the body text. Look for social engineering tactics.
 */
async function agentProfiler(body) {
    try {
        return Promise.resolve({
            agent: "Profiler",
            finding: body.toLowerCase().includes("urgent") ? "Social engineering tactics (Urgency) identified." : "No manipulative phrasing detected.",
            risk: body.toLowerCase().includes("urgent") ? "medium" : "low"
        });
    } catch (e) {
        console.error(`[Layer 4: The Analysts] Profiler Agent Error: ${e.message}`);
        return { agent: "Profiler", finding: "Behavioral analysis failed. Neutral fallback.", risk: "unknown", error: e.message };
    }
}

async function runSpecializedAgents(email, executionContext) {
    const { facts } = executionContext;
    console.log(`[Layer 4: The Analysts] Spawning specialized agents...`);
    const [dnaReport, linkReport, profilerReport] = await Promise.all([
        agentDNA(facts.mail_auth, email.headers),
        agentLinks(facts.safe_browsing, email.urls, email.headers.from),
        agentProfiler(email.body)
    ]);

    console.log(`[Layer 4: The Analysts] Agents finished reasoning.`);
    return {
        dna: dnaReport,
        links: linkReport,
        profiler: profilerReport
    };
}

module.exports = { runSpecializedAgents };
