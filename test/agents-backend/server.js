// server.js
import express from "express";
import cors from "cors";
// Import all four of our AI agents
import { runDnaAgent, runLinkAgent, runProfilerAgent, runJudgeAgent } from "./agents.js";

const app = express();

// Middleware
app.use(cors()); // Allows your Chrome Extension to talk to this server
app.use(express.json()); // Allows the server to understand JSON data

// ==========================================
// ROUTE 1: Health Check (For your browser)
// ==========================================
app.get("/", (req, res) => {
  res.send("🛡️ PhishGuard.AI Backend is active, online, and listening!");
});

// ==========================================
// ROUTE 2: The Main Analysis Engine
// ==========================================
app.post("/analyze-email", async (req, res) => {
  try {
    // 1. Grab the raw data sent by the Chrome Extension
    const { headers, urls, body } = req.body;
    
    console.log("-----------------------------------------");
    console.log("🚨 NEW SCAN INITIATED");
    console.log("-----------------------------------------");

    // 2. Parallel Processing Phase (The Workers)
    console.log("⏳ Step 1: Running DNA, Link, and Profiler agents in parallel...");
    const [dnaReport, linkReport, profilerReport] = await Promise.all([
      runDnaAgent(headers),
      runLinkAgent(urls),
      runProfilerAgent(body)
    ]);
    console.log("✅ Step 1 Complete: Worker reports generated.");

    // 3. Synthesis Phase (The Judge)
    console.log("⏳ Step 2: Passing case file to the Judge for final verdict...");
    const finalVerdict = await runJudgeAgent(dnaReport, linkReport, profilerReport);
    console.log("✅ Step 2 Complete: Final verdict reached.");

    // 4. Send the final verdict back to the user/extension
    res.json(finalVerdict);
    console.log("🚀 Scan successful. Results sent to client.\n");

  } catch (error) {
    // If anything breaks (API limit, bad JSON, etc.), catch it here so the server doesn't crash
    console.error("❌ Error analyzing email:", error);
    res.status(500).json({ 
        error: "Analysis failed.", 
        details: error.message 
    });
  }
});

// ==========================================
// START THE SERVER
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🛡️ PhishGuard.AI Server Started!`);
  console.log(`📡 Listening on http://localhost:${PORT}\n`);
});