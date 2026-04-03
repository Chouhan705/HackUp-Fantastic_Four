require('dotenv').config();
const { analyzeEmail } = require('./src/index');

const maliciousEmail = {
  headers: {
    from: 'support@paypa1.com',
    replyTo: 'hacker@evil.com'
  },
  body: "URGENT URGENT URGENT: Your account has been suspended. Please verify your identity by clicking the link. Call 800-555-1234 for support.",
  urls: ['http://www.paypa1-verify-account.com/login']
};

const safeEmail = {
  headers: {
    from: 'newsletter@github.com',
    replyTo: 'noreply@github.com'
  },
  body: "Here are your weekly repository updates.",
  urls: ['https://github.com/trendings']
};

const nasaEmail = {
  headers: {
    from: 'hq-rsvp@nasa.gov',
    replyTo: 'hq-rsvp@nasa.gov'
  },
  body: "NASA test",
  urls: ['https://www.nasa.gov/virtual-guest']
};

async function runTests() {
  console.log("=== Testing Malicious Email ===");
  const maliciousResult = await analyzeEmail(maliciousEmail);
  console.log(JSON.stringify(maliciousResult, null, 2));

  console.log("\n=== Testing Safe Email ===");
  const safeResult = await analyzeEmail(safeEmail);
  console.log(JSON.stringify(safeResult, null, 2));

  console.log("\n=== Testing NASA Direct Match ===");
  const nasaResult = await analyzeEmail(nasaEmail);
  console.log(JSON.stringify(nasaResult, null, 2));
}

runTests();
