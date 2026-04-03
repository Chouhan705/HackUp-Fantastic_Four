// Content Script injected by the Popup
// It scrapes the current DOM to extract URLs, Text Body, and simulated Headers 
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scrape') {
        const bodyText = document.body.innerText || "";
        
        // Extract ALL anchor links
        let urls = [];
        const anchors = document.querySelectorAll('a[href]');
        anchors.forEach(a => urls.push(a.href));
        
        // Ensure URLs are deduped and max 50 are sent to the AI
        urls = [...new Set(urls)].slice(0, 50);

        // Simulated headers for demonstration
        // A real extension for Gmail would use Gmail's API to extract the real FROM/TO headers.
        const pageDomain = window.location.hostname;
        
        sendResponse({
            data: {
                from: `support@${pageDomain}`,
                replyTo: `support@${pageDomain}`,
                body: bodyText,
                urls: urls
            }
        });
    }
});
