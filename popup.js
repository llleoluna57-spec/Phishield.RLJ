// Minimal scanner logic for the extension popup. Reuses client heuristics.
(() => {
  const suspiciousTLDs = ['tk','ml','ga','cf','gq','zip','review','kim'];
  const phishingWords = ['login','secure','account','update','verify','bank','signin','confirm'];

  function analyzeURL(raw) {
    try {
      let input = raw.trim();
      if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(input)) input = 'http://' + input;
      const url = new URL(input);
      const host = url.hostname;
      const issues = [];
      if (/@/.test(raw)) issues.push('Contains an @ sign');
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) issues.push('Hostname is an IP address');
      if (host.includes('xn--')) issues.push('Punycode in domain');
      const parts = host.split('.').filter(Boolean);
      const tld = parts.length ? parts[parts.length - 1].toLowerCase() : '';
      if (suspiciousTLDs.includes(tld)) issues.push('High-risk TLD: .' + tld);
      if (parts.length >= 4) issues.push('Many subdomains');
      if (host.length > 60) issues.push('Very long hostname');
      if (raw.length > 200) issues.push('Very long URL');
      if (host.includes('-')) issues.push('Hyphen in domain');
      if (url.protocol !== 'https:') issues.push('Not HTTPS');
      for (const w of phishingWords) if ((url.pathname + url.search + url.hash).toLowerCase().includes(w)) issues.push('Phishing keyword: ' + w);
      let verdict = 'Safe';
      if (issues.length >= 4) verdict = 'Fake/Scam';
      else if (issues.length >= 2) verdict = 'Suspicious';
      const score = Math.max(0, 100 - issues.length * 20);
      const category = classifyURL(url, raw);
      return { verdict, issues, score, normalized: url.href, host, category };
    } catch (err) {
      return { verdict: 'Invalid', issues: [err.message], score: 0 };
    }
  }

  function classifyURL(urlObj, raw) {
    try {
      const url = (urlObj && urlObj.href) ? new URL(urlObj.href) : new URL(raw);
      const host = url.hostname.toLowerCase();
      const path = (url.pathname + url.search + url.hash).toLowerCase();
      if (/^sms:/i.test(raw) || url.protocol === 'sms:') return 'SMS Link';
      if (/^tel:/i.test(raw) || url.protocol === 'tel:') return 'Phone Link';
      const fbHosts = ['facebook.com','fb.me','m.facebook.com','l.facebook.com'];
      const ytHosts = ['youtube.com','youtu.be'];
      const shopKeywords = ['amazon','ebay','etsy','aliexpress','walmart','bestbuy','shop','store','checkout'];
      const betKeywords = ['bet','casino','poker','gambling','bookmaker','sportbook','lottery','bingo','slot'];
      const bankKeywords = ['bank','chase','wellsfargo','wells-fargo','capitalone','hsbc','barclays','santander','citibank','natwest','lloyds','rbs','bankofamerica'];
      if (fbHosts.some(h => host.includes(h))) return 'Facebook Link';
      if (ytHosts.some(h => host.includes(h))) return 'YouTube Link';
      if (shopKeywords.some(k => host.includes(k) || path.includes(k))) return 'Online Shopping Link';
      if (betKeywords.some(k => host.includes(k) || path.includes(k))) return 'Online Bet Link';
      if (bankKeywords.some(k => host.includes(k) || path.includes(k))) return 'Bank Link';
      if (path.includes('sms:') || path.includes('send-sms') || host.includes('sms')) return 'SMS Link';
      return 'Other';
    } catch (e) { return 'Other'; }
  }

  function renderResult(res) {
    const verdictEl = document.getElementById('verdict');
    const detailsEl = document.getElementById('details');
    const metaEl = document.getElementById('meta');
    verdictEl.textContent = res.verdict;
    detailsEl.innerHTML = '';
    metaEl.innerHTML = '';
    if (res.issues && res.issues.length) {
      const ul = document.createElement('ul');
      for (const i of res.issues) { const li = document.createElement('li'); li.textContent = i; ul.appendChild(li); }
      detailsEl.appendChild(ul);
    } else {
      detailsEl.textContent = 'No common indicators detected.';
    }
    if (res.normalized) { const d = document.createElement('div'); d.textContent = 'Normalized: ' + res.normalized; metaEl.appendChild(d); }
    const s = document.createElement('div'); s.textContent = 'Score: ' + res.score + '/100'; metaEl.appendChild(s);
    if (res.category) { const c = document.createElement('div'); c.textContent = 'Type: ' + res.category; metaEl.appendChild(c); }
  }

  // keep last result for open confirmation logic
  let lastScanResult = null;

  const origRender = renderResult;
  renderResult = function(res) {
    lastScanResult = res;
    origRender(res);
  };

  // Utility: get current active tab URL
  function getActiveTabUrl(callback) {
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || !tabs[0]) return callback(null);
        callback(tabs[0].url);
      });
    } catch (e) { callback(null); }
  }

  // Server scan helper
  function serverScan(url, apiEndpoint, onResult) {
    if (!apiEndpoint) return onResult(null);
    fetch(apiEndpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }) })
      .then(r => r.json()).then(j => onResult(j)).catch(() => onResult(null));
  }

  document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const clearBtn = document.getElementById('clearBtn');
    const scanTab = document.getElementById('scanTab');
    const urlInput = document.getElementById('urlInput');
    const apiInput = document.getElementById('apiEndpoint');
    const saveApi = document.getElementById('saveApi');

    // load saved api endpoint
    chrome.storage.sync.get(['ph_api'], (items) => { if (items.ph_api) apiInput.value = items.ph_api; });

    saveApi.addEventListener('click', () => {
      const val = apiInput.value.trim();
      chrome.storage.sync.set({ ph_api: val }, () => alert('API endpoint saved'));
    });

    scanBtn.addEventListener('click', () => {
      const val = urlInput.value.trim();
      if (!val) return alert('Enter a URL or use Scan Current Tab');
      const res = analyzeURL(val);
      renderResult(res);
      chrome.storage.sync.get(['ph_api'], (items) => { const api = items.ph_api || null; serverScan(val, api, (j) => { if (j) { const meta = document.getElementById('meta'); const s = document.createElement('pre'); s.style.fontSize='11px'; s.style.whiteSpace='pre-wrap'; s.textContent = JSON.stringify(j, null, 2); meta.appendChild(s); } }); });
    });

    clearBtn.addEventListener('click', () => { document.getElementById('verdict').textContent = 'No scan yet'; document.getElementById('details').innerHTML=''; document.getElementById('meta').innerHTML=''; urlInput.value=''; });

    scanTab.addEventListener('click', () => {
      getActiveTabUrl((tabUrl) => {
        if (!tabUrl) return alert('Unable to get active tab URL');
        urlInput.value = tabUrl;
        const res = analyzeURL(tabUrl);
        renderResult(res);
        chrome.storage.sync.get(['ph_api'], (items) => { const api = items.ph_api || null; serverScan(tabUrl, api, (j) => { if (j) { const meta = document.getElementById('meta'); const s = document.createElement('pre'); s.style.fontSize='11px'; s.style.whiteSpace='pre-wrap'; s.textContent = JSON.stringify(j, null, 2); meta.appendChild(s); } }); });
      });
    });

    const reportBtn = document.getElementById('reportBtn');
    reportBtn.addEventListener('click', () => {
      const url = urlInput.value.trim();
      if (!url) return alert('Enter a URL or scan current tab first');
      chrome.storage.sync.get(['ph_api'], (items) => {
        const api = items.ph_api || null;
        if (!api) return alert('No server API endpoint saved. Save it in the Server API endpoint field.');
        fetch(api.replace(/\/api\/scan\/?$/, '/api/report'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url, reason: 'reported via extension' }) })
          .then(r => r.json()).then(j => { if (j && j.ok) alert('Report submitted. Thank you.'); else alert('Report failed.'); }).catch(()=>alert('Report failed.'));
      });
    });
    const openBtn = document.getElementById('openBtn');
    openBtn.addEventListener('click', () => {
      const url = urlInput.value.trim();
      if (!url) return alert('Enter a URL or scan current tab first');
      if (lastScanResult && (lastScanResult.verdict === 'Suspicious' || lastScanResult.verdict === 'Fake/Scam')) {
        const expected = lastScanResult.host || (() => { try { return (new URL(url)).hostname } catch(e){ return '' } })();
        const typed = prompt('This site was flagged as ' + lastScanResult.verdict + '. Type the domain to confirm opening:');
        if (!typed || typed.trim() !== expected) return alert('Confirmation failed. Not opening.');
      }
      try { chrome.tabs.create({ url }); } catch (e) { window.open(url, '_blank'); }
    });
  });
})();
