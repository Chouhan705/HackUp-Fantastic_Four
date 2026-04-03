document.getElementById('scanBtn').addEventListener('click', async () => {
    const scanBtn = document.getElementById('scanBtn');
    const loading = document.getElementById('loading');
    const resultBox = document.getElementById('result');
    
    // UI Loading state
    scanBtn.disabled = true;
    scanBtn.innerText = 'Scanning...';
    resultBox.style.display = 'none';
    loading.style.display = 'block';

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Inject content.js into the current tab to scrape the DOM
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['content.js']
    }, () => {
      // Send a message to the content script asking for scraped data
      chrome.tabs.sendMessage(tab.id, { action: 'scrape' }, async (response) => {
          if (!response) {
              displayError("Could not connect to page. Make sure you are on a real webpage.");
              return;
          }

          try {
            // Forward scraped data to our Node.js Backend API
            const backendResponse = await fetch('http://localhost:3000/api/analyze', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(response.data)
            });

            if (!backendResponse.ok) throw new Error("Backend API down.");

            const verdict = await backendResponse.json();
            displayVerdict(verdict);
            
          } catch (e) {
            displayError(`Failed to reach the 5-Layer Hybrid ML Pipeline. Is your server.js running?\n\nError: ${e.message}`);
          }
      });
    });
});

function displayVerdict(verdict) {
    const loading = document.getElementById('loading');
    const resultBox = document.getElementById('result');
    const threatHeader = document.getElementById('threatLevel');
    const threatScore = document.getElementById('threatScore');
    const scanBtn = document.getElementById('scanBtn');
    const summary = document.getElementById('summary');
    const logicPath = document.getElementById('logicPath');
    const metricsGrid = document.getElementById('metricsGrid');
    const evidenceList = document.getElementById('evidence');
    const evidenceTitle = document.getElementById('evidenceTitle');

    loading.style.display = 'none';
    resultBox.style.display = 'block';
    
    // Clear old colors and set the new one
    resultBox.className = '';
    resultBox.classList.add(verdict.status);

    threatHeader.innerText = verdict.status;
    threatScore.innerText = Math.round(verdict.score);
    
    summary.innerText = verdict.recommendation;      

    // Populate Logic Path
    if (verdict.logic_path) {
        logicPath.innerText = verdict.logic_path.replace(/ \-> /g, '\n↓\n');
    }

    // Populate Metrics Grid
    metricsGrid.innerHTML = '';
    const addMetric = (label, value) => {
        metricsGrid.innerHTML += `
            <div class="data-row">
                <span class="data-label">${label}</span>
                <span class="data-value">${value}</span>
            </div>
        `;
    };

    if (verdict.forensics) {
        addMetric("Trust Deficit", verdict.forensics.trust_deficit ? "Detected" : "None");
        addMetric("URL Obfuscation", verdict.forensics.url_obfuscated ? "Detected" : "Clean");
        const flagsCount = (verdict.forensics.behavior_flags || []).length;
        addMetric("Behavior Flags", flagsCount > 0 ? flagsCount : "None");
    }

    // Clear and populate Evidence list
    evidenceList.innerHTML = '';
    
    const addLi = (badgeClass, badgeText, text, liClass) => {
        const li = document.createElement('li');
        if (liClass) li.classList.add(liClass);
        li.innerHTML = `<span class="badge ${badgeClass}">${badgeText}</span> ${text}`;
        evidenceList.appendChild(li);
    };

    if (verdict.forensics) {
        if (verdict.forensics.trust_deficit) {
            addLi('red', 'CRITICAL', 'Significant trust deficit detected in identity parsing.', 'flag-high');
        }
        if (verdict.forensics.url_obfuscated) {
             addLi('yellow', 'WARNING', 'URL shortening or obfuscation techniques found.', 'flag-med');
        }
        if (verdict.forensics.behavior_flags && verdict.forensics.behavior_flags.length > 0) {
            verdict.forensics.behavior_flags.forEach(flag => {
                addLi('yellow', 'FLAG', flag, 'flag-med');
            });
        }
        if (verdict.forensics.reason) {
            addLi('blue', 'INFO', verdict.forensics.reason, 'flag-info');
        }
        if (verdict.forensics.evidence) {
            verdict.forensics.evidence.forEach(evi => {
                addLi('yellow', 'EVIDENCE', evi, 'flag-med');
            });
        }
        if (verdict.forensics.error) {
            addLi('red', 'ERROR', verdict.forensics.error, 'flag-high');
        }
    }
    
    if (evidenceList.children.length > 0) {
        evidenceTitle.style.display = 'block';
    } else {
        evidenceTitle.style.display = 'none';
        addLi('green', 'CLEAN', 'No malicious signatures or anomalies detected.', 'flag-info');
    }

    scanBtn.innerText = 'Run Analysis Again';
    scanBtn.disabled = false;
}

function displayError(msg) {
    const loading = document.getElementById('loading');
    const resultBox = document.getElementById('result');
    loading.style.display = 'none';
    
    resultBox.style.display = 'block';
    resultBox.className = 'BLOCKED';
    
    const threatLevel = document.getElementById('threatLevel');
    if (threatLevel) threatLevel.innerText = "ERROR";
    
    const threatScore = document.getElementById('threatScore');
    if (threatScore) threatScore.innerText = "--";
    
    const summary = document.getElementById('summary');
    if (summary) summary.innerText = msg;
    
    const evidenceList = document.getElementById('evidence');
    if (evidenceList) evidenceList.innerHTML = '';
    
    const scanBtn = document.getElementById('scanBtn');
    if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.innerText = 'Retry Connection';
    }
}

