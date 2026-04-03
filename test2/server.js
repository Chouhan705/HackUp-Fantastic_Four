require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { analyzeEmail } = require('./src/index');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.post('/api/analyze', async (req, res) => {
  try {
    const { from, replyTo, body, urls } = req.body;
    
    const rawEmail = {
      headers: {
        from: from || "unknown@unknown.com",
        replyTo: replyTo || "unknown@unknown.com"
      },
      body: body || "",
      urls: urls || []
    };

    console.log(`[API] Analyzing email from: ${rawEmail.headers.from}`);
    const verdict = await analyzeEmail(rawEmail);
    res.json(verdict);
  } catch (error) {
    console.error(`[API Error]`, error);
    res.status(500).json({ error: error.message });
  }
});

const server = app.listen(PORT, () => {
  console.log(`\n=== NoPhishZone Backend Running on http://localhost:${PORT} ===\n`);
});

server.on('error', (err) => {
  console.error('Server error:', err);
});

process.on('exit', (code) => {
  console.log('Process exiting with code:', code);
});
