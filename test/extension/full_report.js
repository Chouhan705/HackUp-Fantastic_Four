// Read real report data from storage
if (typeof chrome !== 'undefined' && chrome.storage) {
    chrome.storage.local.get('lastReport', ({ lastReport }) => {
      if (!lastReport) return;
      const r = lastReport;
      const color = r.score >= 70 ? '#ff2d55' : r.score >= 40 ? '#ffd60a' : '#30d158';
   
      document.querySelector('.score-num').textContent = r.score + '%';
      document.querySelector('.score-num').style.color = color;
      document.querySelector('.score-num').style.textShadow = `0 0 30px ${color}`;
      document.querySelector('.badge').textContent = r.threatLevel + ' THREAT';
      document.querySelector('.badge').style.borderColor = color;
      document.querySelector('.badge').style.color = color;
   
      // Populate findings
      const findingsEl = document.querySelector('.card:last-of-type p');
      if (findingsEl && r.findings) {
        findingsEl.textContent = r.findings.join(' · ');
      }
    });
  }