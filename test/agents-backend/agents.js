// agents.js
import { GoogleGenerativeAI } from "@google/generative-ai";
import dotenv from "dotenv";

dotenv.config(); // Loads your API key from the .env file

// Initialize Gemini
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Helper function to create an agent
async function runAgent(systemPrompt, inputData) {
  // We use flash-lite for extreme speed in the hackathon
  const model = genAI.getGenerativeModel({ 
    model: "gemini-2.5-flash",
    systemInstruction: systemPrompt,
    generationConfig: { 
        responseMimeType: "application/json" // CRITICAL: Forces Gemini to only output JSON
    }
  });

  const prompt = JSON.stringify(inputData);
  const result = await model.generateContent(prompt);
  
  // Convert Gemini's text response into a real JavaScript object
  return JSON.parse(result.response.text());
}

// Agent 1: DNA Detective
export async function runDnaAgent(headers) {
  const prompt = `You are a Senior Mail Server Architect. Analyze these email headers.
  Output JSON format: {"is_spoofed": boolean, "auth_score": number 0-100, "technical_summary": "string"}`;
  return await runAgent(prompt, headers);
}

// Agent 2: Link Hunter
export async function runLinkAgent(urls) {
  const prompt = `You are a Cyber-Threat Intelligence specialist. Analyze these URLs for typosquatting and risks.
  Output JSON format: {"malicious_urls": ["string"], "link_risk_score": number 0-100, "hunter_note": "string"}`;
  return await runAgent(prompt, urls);
}

// Agent 3: Profiler
// Agent 3: Profiler
export async function runProfilerAgent(body, fromAddress) {
  const systemPrompt = `You are an Expert in Social Engineering. Analyze this email text.
  CRITICAL IMPERSONATION CHECK: The email was actually sent by: "${fromAddress}". 
  Read the body text. Does the email claim to be from a completely different company, brand, or organization (e.g., sent by a personal Gmail but claims to be Google, Apple, or Gemini Team)? 
  If they do not match, flag it as a HIGH RISK Impersonation attempt.
  
  Output JSON format: {"is_ai_generated": boolean, "manipulation_score": number 0-100, "profiler_summary": "string"}`;
  
  return await runAgent(systemPrompt, body);
}
// Agent 4: The Judge (Aggregator)
export async function runJudgeAgent(dnaReport, linkReport, profilerReport) {
  const systemPrompt = `You are the Lead Forensic Judge for PhishGuard.AI. 
  Your job is to read the reports from your three specialist agents and determine the final threat level.
  
  Output ONLY JSON format: 
  {
    "final_risk_score": number (0-100), 
    "threat_level": "Safe" | "Suspicious" | "Dangerous" | "Critical", 
    "user_friendly_summary": "A 2-sentence plain English explanation of why this email is dangerous, meant for a non-technical user.", 
    "key_evidence": ["string", "string", "string"] 
  }`;

  // Package the three reports together as the input data
  const caseFile = {
    dna_evidence: dnaReport,
    link_evidence: linkReport,
    behavioral_evidence: profilerReport
  };

  return await runAgent(systemPrompt, caseFile);
}