// test.js

async function runTest() {
  console.log("🚀 Sending safe sample email data to PhishGuard.AI backend...\n");

  // This is safe sample data your Chrome Extension can send
const fakeEmailData = {
    headers: {
        "From": "Aditya Chouhan <aditya.chouhan@gmail.com>",
        "Return-Path": "<aditya.chouhan@gmail.com>",
        "Authentication-Results": "spf=pass (sender IP is 203.0.113.10); dkim=pass; dmarc=pass",
        "Message-ID": "<20260403.abc123@gmail.com>"
    },
    urls: [
        "https://www.example.com/account/help"
    ],
    body: `Hello Aditya,

We are writing to inform you of upcoming changes to Google AI Studio Usage Tiers. Starting April 1, 2026, we’re implementing enforced monthly spending limits for the Gemini API at the billing account level. These limits are designed to help you manage costs effectively as you scale.

We’ve provided additional information below about the usage tiers and the actions you need to take to help you with the transition.

What you need to know
Starting April 1, 2026, Tier 1 will have a monthly gross spending limit of $250 (including credits). If your total spending reaches this limit, your Gemini API requests associated with your billing account will be paused until the next month.

How to increase your limit:

Tier upgrades are now automated. Once you meet the following threshold, you will automatically graduate to Tier 2, increasing your monthly limit to $2,000 and raising your rate limits:

$100 in total payments: You must have paid at least $100 via Google Cloud payments.
Note: Credits do not apply toward this total.
3-day waiting period: At least 3 days must have passed since your first successful payment.
What you need to do
We recommend completing the following actions before April 1, 2026, to prevent service disruption as your usage increases:

Ensure your projects are imported: If you haven't already, import any projects that you want to be upgraded to a paid tier into Google AI Studio.
Check your progress: Log in to Google AI Studio to view your current usage for your imported projects, applicable limits, and your progress toward Tier 2.
Request an override: If you anticipate an immediate usage increase that will exceed your current tier’s limits before the automated upgrade occurs, please complete this form to request a limit increase.
We’re here to help
We understand that such transitions require careful planning. If you have any questions or need help, please check our product documentation or visit the Gemini AI community.

Thanks for choosing Google AI Studio and Gemini API.

– The Gemini API Team`
};

  try {
    // Send the POST request to our local server
    const response = await fetch("http://localhost:3000/analyze-email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(fakeEmailData)
    });

    if (!response.ok) {
      throw new Error(`Server returned status: ${response.status}`);
    }

    // Parse and print the result from the 3 AI Agents
    const result = await response.json();
    
    console.log("✅ ANALYSIS COMPLETE! Here are the Agent Reports:\n");
    console.log(JSON.stringify(result, null, 2));

  } catch (error) {
    console.error("❌ Test failed. Is your server running?", error.message);
  }
}

// Execute the test
runTest();