// popup/popup.js

const scanBtn   = document.getElementById("scan-btn");
const note      = document.getElementById("note");
const footer    = document.getElementById("result-footer");
const breakdown = document.getElementById("breakdown");

scanBtn.addEventListener("click", () => {
  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";
  note.textContent = "Analyzing website...";
  breakdown.style.display = "none";
  breakdown.innerHTML = "";

  // Get the current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) {
      showError("Could not find active tab.");
      return;
    }

    const activeTab = tabs[0];
    const url = activeTab.url;
    const title = activeTab.title;

    // Execute script to get page HTML/text if needed
    chrome.scripting.executeScript({
      target: { tabId: activeTab.id },
      func: () => document.body.innerText
    }, (injectionResults) => {
      let pageText = "";
      if (injectionResults && injectionResults[0] && injectionResults[0].result) {
        pageText = injectionResults[0].result;
      }

      sendDataToBackend(url, title, pageText.substring(0, 5000)); // Send first 5k chars
    });
  });
});

function sendDataToBackend(url, title, content) {
  fetch("http://localhost:8000/scan-website", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      url: url,
      title: title,
      content: content
    })
  })
  .then(response => {
    if (!response.ok) throw new Error("Server Error " + response.status);       
    return response.json();
  })
  .then(data => {
    scanBtn.disabled = false;
    scanBtn.textContent = "Scan Again";
    scanBtn.style.background = "#639922";

    // Display results
    const verdict = data.verdict ? data.verdict.toUpperCase() : "UNKNOWN";      
    const score = data.score || 0;

    note.innerHTML = `<strong>Verdict: ${verdict}</strong> (Score: ${score}/100)`;

    // Map new coloring and shadow to the button
    if (verdict === "PHISHING" || verdict === "SUSPICIOUS") {
      note.style.color = "#a32d2d";
      scanBtn.style.background = "#d32f2f";
      scanBtn.style.boxShadow = "0 4px 10px rgba(211,47,47,0.3)";
    } else {
      note.style.color = "#3b6d11";
       scanBtn.style.background = "#639922";
       scanBtn.style.boxShadow = "0 4px 10px rgba(99,153,34,0.3)";
    }

    if (data.explanation) {
      breakdown.style.display = "block";
      breakdown.innerHTML = "<strong>Explanation:</strong><br>" + data.explanation;
    }

    footer.textContent = `Scanned URL: ${url.substring(0, 30)}...`;
  })
  .catch(err => {
    showError(err.message);
  });
}

function showError(msg) {
  scanBtn.disabled = false;
  scanBtn.textContent = "Scan This Website";
  scanBtn.style.background = "#1a73e8";
  scanBtn.style.boxShadow = "0 4px 10px rgba(26,115,232,0.3)";
  note.textContent = "Error: " + msg;
  note.style.color = "#a32d2d";
  breakdown.style.display = "none";
  footer.textContent = "Scan failed: " + msg;
}
