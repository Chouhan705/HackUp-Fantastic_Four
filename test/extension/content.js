// content.js
let lastEmailId = null;

function checkUrlForEmail() {
  const url = window.location.hash; // Gmail uses hashes for navigation
  const match = url.match(/#inbox\/([a-zA-Z0-9]+)/);
  
  if (match && match[1] !== lastEmailId) {
    lastEmailId = match[1];
    console.log("[PhishGuard.AI] Detected opened email:", lastEmailId);
    
    // Notify the extension to start an automatic forensic scan
    chrome.runtime.sendMessage({
      type: "EMAIL_OPENED",
      emailId: lastEmailId
    });
  }
}

// Watch for URL changes (SPA navigation)
window.addEventListener('hashchange', checkUrlForEmail);
// Initial check in case they refresh while an email is open
checkUrlForEmail();