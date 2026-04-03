require('dotenv').config();
const fs = require('fs');
const { simpleParser } = require('mailparser');
const { analyzeEmail } = require('./src/index');

/**
 * Extracts all URLs from text content
 */
function extractUrls(text) {
  const urlRegex = /(https?:\/\/[^\s<>'"]+)/g;
  const matches = text.match(urlRegex) || [];
  return [...new Set(matches)]; // Deduplicate URLs
}

async function processEmlFile(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      console.error(`[Error] File not found: ${filePath}`);
      return;
    }

    console.log(`\n=== Loading Real Email: ${filePath} ===`);
    const emailContent = fs.readFileSync(filePath, 'utf8');
    
    // Parse the .eml file format into a readable object
    const parsed = await simpleParser(emailContent);

    // Safely extract the primary From address
    let fromAddress = "unknown";
    if (parsed.from && parsed.from.value && parsed.from.value.length > 0) {
      fromAddress = parsed.from.value[0].address;
    }

    // Safely extract the Reply-To address
    let replyToAddress = fromAddress; // default to 'From' if 'Reply-To' is blank
    if (parsed.replyTo && parsed.replyTo.value && parsed.replyTo.value.length > 0) {
      replyToAddress = parsed.replyTo.value[0].address;
    }

    // Grab the text version of the body
    const bodyText = parsed.text || parsed.textAsHtml || "";
    
    // Extract URLs from both HTML (hrefs) and plaintext body
    const htmlUrls = parsed.html ? extractUrls(parsed.html) : [];
    const textUrls = extractUrls(bodyText);
    const allUrls = [...new Set([...htmlUrls, ...textUrls])];

    // Construct the rawEmail object exactly as analyzeEmail() expects
    const rawEmail = {
      headers: {
        from: fromAddress,
        replyTo: replyToAddress
      },
      body: bodyText,
      urls: allUrls
    };

    console.log(`[Extracted] From: ${rawEmail.headers.from} | Reply-To: ${rawEmail.headers.replyTo}`);
    console.log(`[Extracted] URLs Found: ${rawEmail.urls.length}`);
    rawEmail.urls.forEach(u => console.log(`  - ${u}`));
    console.log(`-------------------------------------------------\n`);

    // Feed to the Waterfall Architecture
    const result = await analyzeEmail(rawEmail);
    
    console.log("\n=== FINAL VERDICT ===");
    console.log(JSON.stringify(result, null, 2));

  } catch (error) {
    console.error(`[Fatal Error] Could not process ${filePath}:`, error);
  }
}

// Grab the filename from the command line arguments
const targetFile = process.argv[2];

if (targetFile) {
  processEmlFile(targetFile);
} else {
  console.log(`
Usage: node test-real-email.js <path-to-eml-file>

Example:
  node test-real-email.js ./sample_emails/phishing_1.eml
  `);
}
