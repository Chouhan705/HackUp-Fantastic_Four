/**
 * ─── GMAIL DOM OBSERVER ───
 */
let lastEmailId = null;

/**
 * Extracts the message ID from the Gmail URL hash and signals the extension.
 * Gmail Hash Pattern: #inbox/MSG_ID or #sent/MSG_ID etc.
 */
function checkUrlForEmail() {
    const urlHash = window.location.hash;
    // Regular expression to capture the hexadecimal ID at the end of the Gmail route
    const match = urlHash.match(/#\w+\/([a-zA-Z0-9]+)/);
    
    if (match && match[1] !== lastEmailId) {
        lastEmailId = match[1];
        
        console.log("🕵️ [PhishGuard.AI] Gmail Navigation Detected. Target ID:", lastEmailId);
        
        // Notify the extension's Background Script and Popup/Side Panel
        chrome.runtime.sendMessage({
            type: "EMAIL_OPENED",
            emailId: lastEmailId
        });
    }
}

/**
 * ─── EVENT LISTENERS ───
 */

// 1. Watch for URL changes (navigation between emails)
window.addEventListener('hashchange', checkUrlForEmail);

// 2. Initial check in case the user refreshes the page while an email is already open
document.addEventListener('DOMContentLoaded', () => {
    // Small delay to ensure Gmail's SPA router has finished loading the initial hash
    setTimeout(checkUrlForEmail, 1000);
});

/**
 * ─── UI INJECTION (OPTIONAL / HACKATHON BONUS) ───
 * This demonstrates that the extension is "alive" inside the Gmail interface.
 */
console.log("🛡️ [PhishGuard.AI] Content Script Injected. Monitoring Forensic Vectors...");