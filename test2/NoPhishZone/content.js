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

        const pageDomain = window.location.hostname;

        // Default headers if we can't scrape them
        let fromHeader = `unknown_sender@${pageDomain}`;
        let replyToHeader = `unknown_sender@${pageDomain}`;
        
        if (pageDomain.includes('mail.google.com')) {
            // Gmail stores the sender email in a span with class "gD" and attribute "email"
            // For email threads, get the last "gD" which corresponds to the latest email
            const senderSpans = document.querySelectorAll('span.gD');
            if (senderSpans && senderSpans.length > 0) {
                const latestSender = senderSpans[senderSpans.length - 1];
                if (latestSender.hasAttribute('email')) {
                    fromHeader = latestSender.getAttribute('email');
                    replyToHeader = fromHeader; // Fallback
                }
            }
        }

        sendResponse({
            data: {
                from: fromHeader,
                replyTo: replyToHeader,
                body: bodyText,
                urls: urls
            }
        });
    }
});
