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
    const scanBtn = document.getElementById('scanBtn');

    loading.style.display = 'none';
    resultBox.style.display = 'block';
    
    // Clear old colors and set the new one
    resultBox.className = '';
    resultBox.classList.add(verdict.status);

    threatHeader.innerText = `${verdict.status} (Score: ${verdict.score})`;     
    threatHeader.style.color = (verdict.status === 'BLOCKED' || verdict.status === 'WARNING') ? 'red' : 'green';

    document.getElementById('summary').innerText = verdict.recommendation;      

    const evidenceList = document.getElementById('evidence');
    evidenceList.innerHTML = '';
    
    // Add logic path and forensics to evidence
    const pathLi = document.createElement('li');
    pathLi.innerText = `Logic Path: ${verdict.logic_path}`;
    evidenceList.appendChild(pathLi);

    if (verdict.forensics) {
        if (verdict.forensics.trust_deficit) {
            const li = document.createElement('li');
            li.innerText = 'Trust Deficit Detected';
            evidenceList.appendChild(li);
        }
        if (verdict.forensics.url_obfuscated) {
             const li = document.createElement('li');
             li.innerText = 'URL Obfuscation Detected';
             evidenceList.appendChild(li);
        }
        if (verdict.forensics.behavior_flags && verdict.forensics.behavior_flags.length > 0) {
            verdict.forensics.behavior_flags.forEach(flag => {
                const li = document.createElement('li');
                li.innerText = `Flag: ${flag}`;
                evidenceList.appendChild(li);
            });
        }
        if (verdict.forensics.reason) {
            const li = document.createElement('li');
            li.innerText = `Reason: ${verdict.forensics.reason}`;
            evidenceList.appendChild(li);
        }
        if (verdict.forensics.evidence) {
            verdict.forensics.evidence.forEach(evi => {
                const li = document.createElement('li');
                li.innerText = `Evidence: ${evi}`;
                evidenceList.appendChild(li);
            });
        }
        if (verdict.forensics.error) {
            const li = document.createElement('li');
            li.innerText = `Error Check: ${verdict.forensics.error}`;
            evidenceList.appendChild(li);
        }
    }
    scanBtn.innerText = 'Scan Again';
}

function displayError(msg) {
    const loading = document.getElementById('loading');
    const resultBox = document.getElementById('result');
    loading.style.display = 'none';
    
    resultBox.style.display = 'block';
    resultBox.className = 'Critical';
    document.getElementById('threatLevel').style.color = 'red';
    document.getElementById('threatLevel').innerText = "Connection Error";
    document.getElementById('summary').innerText = msg;
    document.getElementById('evidence').innerHTML = '';
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('scanBtn').innerText = 'Scan Current Page';
}

