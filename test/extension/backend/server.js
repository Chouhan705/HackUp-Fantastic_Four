// server.js — PhishGuard.AI Express Backend

const express    = require('express');
const cors       = require('cors');
const { fetchLatestEmails } = require('./acquisition');
const { processEmailAnalysis } = require('./agents'); // ⬅️ Imported our Master AI Orchestrator

const app  = express();
const PORT = 3000;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());

// Allow only the Chrome extension to call this server
app.use(cors({
  origin: (origin, cb) => {
    // Chrome extensions have origin like: chrome-extension://<id>
    if (!origin || origin.startsWith('chrome-extension://')) return cb(null, true);
    // Allow localhost testing for Postman/cURL
    if (!origin || origin.startsWith('http://localhost')) return cb(null, true); 
    cb(new Error('Not allowed by CORS'));
  },
}));

// ── Routes ────────────────────────────────────────────────────────────────────

// Health check
app.get('/ping', (req, res) => res.json({ status: 'ok', service: 'PhishGuard.AI' }));

// POST /fetch-and-analyze
// Body: { accessToken: string, maxResults?: number }
// Fetches latest emails from Gmail, runs Hybrid AI analysis on each, returns results
app.post('/fetch-and-analyze', async (req, res) => {
  const { accessToken, maxResults = 5 } = req.body;

  if (!accessToken) {
    return res.status(400).json({ error: 'accessToken is required' });
  }

  try {
    console.log(`📥 Fetching top ${maxResults} emails from Gmail...`);
    // Step 1: Fetch emails (acquisition.js)
    const emails = await fetchLatestEmails(accessToken, maxResults);

    // Step 2: Analyze each email using the AI Swarm concurrently
    console.log("🧠 Unleashing the AI Swarm on batch...");
    
    // ⬅️ CRITICAL UPDATE: We must use Promise.all because processEmailAnalysis is async
    const results = await Promise.all(
        emails.map(async (email) => {
            try {
                return await processEmailAnalysis(email);
            } catch (err) {
                console.error(`🚨 AI Analysis failed for email ${email.id}:`, err.message);
                // Graceful fallback if one email fails so the whole batch doesn't crash
                return { is_phishing: false, final_risk_score: 0, error: "Analysis failed" };
            }
        })
    );

    // Step 3: Sort by final risk score — highest first
    // ⬅️ Updated to use final_risk_score from the new JSON schema
    results.sort((a, b) => (b.final_risk_score || 0) - (a.final_risk_score || 0));

    console.log("✅ Batch analysis complete.");
    return res.json({ success: true, count: results.length, results });

  } catch (err) {
    console.error('[PhishGuard] Error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// POST /analyze-one
// Body: { accessToken: string, emailId: string }
// Fetches and analyzes a single email by Gmail message ID
app.post('/analyze-one', async (req, res) => {
  const { accessToken, emailId } = req.body;

  if (!accessToken || !emailId) {
    return res.status(400).json({ error: 'accessToken and emailId are required' });
  }

  try {
    console.log(`🔎 Searching for specific email ID: ${emailId}`);
    const emails  = await fetchLatestEmails(accessToken, 20);
    const target  = emails.find(e => e.id === emailId);

    if (!target) return res.status(404).json({ error: 'Email not found' });

    console.log("🧠 Routing target to AI Engine...");
    // ⬅️ CRITICAL UPDATE: Await the hybrid agentic process
    const result = await processEmailAnalysis(target);
    
    return res.json({ success: true, result });

  } catch (err) {
    console.error('[PhishGuard] Error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🛡️ PhishGuard.AI backend running → http://localhost:${PORT}`);
});