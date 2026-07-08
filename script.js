// Enhanced client-side anti-phishing heuristics for demo purposes.
const suspiciousTLDs = ['tk','ml','ga','cf','gq','zip','review','kim'];
const phishingWords = ['login','secure','account','update','verify','bank','signin','confirm'];
const localBlocklist = ['malicious.example', 'phishingsite.test'];

// Configurable server API endpoint. Priority:
// 1) window.__PHISHIELD_API_URL__ (set at build/runtime)
// 2) <meta name="phishield-api" content="...">
// 3) default '/api/scan'
let API_ENDPOINT = '/api/scan';
try {
  if (typeof window !== 'undefined' && window.__PHISHIELD_API_URL__) API_ENDPOINT = window.__PHISHIELD_API_URL__;
  else {
    const m = (typeof document !== 'undefined') && document.querySelector('meta[name="phishield-api"]');
    if (m && m.getAttribute('content')) API_ENDPOINT = m.getAttribute('content');
  }
} catch (e) {}

function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  const dp = Array.from({length: m+1}, () => new Array(n+1).fill(0));
  for (let i=0;i<=m;i++) dp[i][0]=i;
  for (let j=0;j<=n;j++) dp[0][j]=j;
  for (let i=1;i<=m;i++) for (let j=1;j<=n;j++) dp[i][j] = Math.min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1] + (a[i-1]===b[j-1]?0:1));
  return dp[m][n];
}

function analyzeURL(raw) {
  try {
    let input = raw.trim();
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(input)) {
      input = 'http://' + input;
    }
    const url = new URL(input);
    const host = url.hostname;
    const issues = [];

    if (/@/.test(raw)) issues.push('Contains an @ sign (credential redirection trick)');
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) issues.push('Hostname is an IP address');
    if (host.includes('xn--')) issues.push('Punycode in domain (potential IDN homograph)');
    const parts = host.split('.').filter(Boolean);
    const tld = parts.length ? parts[parts.length - 1].toLowerCase() : '';
    if (suspiciousTLDs.includes(tld)) issues.push('Uses a high-risk / free TLD: .' + tld);
    // local blocklist check
    if (localBlocklist.includes(host)) issues.push('Domain appears on local blocklist');
    // entropy check for randomized domains
    const entropy = sha1Entropy(host);
    if (entropy > 3.8) issues.push('Hostname has high entropy (likely auto-generated): ' + entropy.toFixed(2));
    // suspicious port
    if (url.port && url.port !== '' && !['80','443'].includes(url.port)) issues.push('Non-standard port detected: ' + url.port);
    // check for phishing keywords in path or query
    const path = url.pathname + url.search + url.hash;
    for (const w of phishingWords) if (path.toLowerCase().includes(w)) issues.push('Contains phishing keyword: ' + w);
    if (parts.length >= 4) issues.push('Many subdomains — possible lookalike');
    if (host.length > 60) issues.push('Very long hostname');
    if (raw.length > 200) issues.push('Very long URL');
    if (host.includes('-')) issues.push('Hyphen in domain (commonly used by phishing domains)');
    if (url.protocol !== 'https:') issues.push('Site does not use HTTPS');

    // lookalike detection vs popular brands (small sample list)
    const known = ['paypal','google','facebook','microsoft','apple','amazon','bank'];
    const domainOnly = parts.slice(-2).join('.');
    const label = parts.length?parts[parts.length-2]||parts[0]:host;
    for (const k of known) {
      const dist = levenshtein(label.toLowerCase(), k.toLowerCase());
      if (dist > 0 && dist <= 2) issues.push('Lookalike domain similar to "' + k + '"');
    }

    // simple scoring
    let score = 100;
    score -= Math.min(75, issues.length * 25);
    if (score < 0) score = 0;

    // Map verdicts to clearer categories
    let verdict = 'Safe';
    if (issues.length >= 4) verdict = 'Fake/Scam';
    else if (issues.length >= 2) verdict = 'Suspicious';

    const category = classifyURL(url, raw);

    return {
      verdict,
      issues,
      score,
      category,
      normalized: url.href,
      host,
      path
    };
  } catch (err) {
    return {
      verdict: 'Invalid',
      issues: [err.message],
      score: 0
    };
  }
}

function classifyURL(urlObj, raw) {
  try {
    const url = (urlObj && urlObj.href) ? new URL(urlObj.href) : new URL(raw);
    const host = url.hostname.toLowerCase();
    const path = (url.pathname + url.search + url.hash).toLowerCase();

    // SMS link (sms: or sms scheme)
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

    // Simple SMS-like short links (mms gateways) or sms query params
    if (path.includes('sms:') || path.includes('send-sms') || host.includes('sms')) return 'SMS Link';

    return 'Other';
  } catch (e) { return 'Other'; }
}

function sha1Entropy(s) {
  // crude character-class based entropy estimate
  const counts = {};
  for (let ch of s) counts[ch] = (counts[ch] || 0) + 1;
  const len = s.length;
  let ent = 0;
  for (let k in counts) {
    const p = counts[k] / len;
    ent -= p * Math.log2(p);
  }
  return ent; // bits per character-ish
}

function renderResult(res) {
  const verdictEl = document.getElementById('verdict');
  const detailsEl = document.getElementById('details');
  const metaEl = document.getElementById('meta');
  const guidanceEl = document.getElementById('guidance');
  const examplesEl = document.getElementById('examples');

  detailsEl.innerHTML = '';
  metaEl.innerHTML = '';

  const badge = document.createElement('span');
  let cls = 'invalid';
  if (res.verdict === 'Safe') cls = 'valid';
  else if (res.verdict === 'Suspicious') cls = 'suspicious';
  else if (res.verdict === 'Fake/Scam') cls = 'dangerous';
  badge.className = 'status-bubble ' + cls;
  badge.textContent = res.verdict;

  verdictEl.innerHTML = '';
  verdictEl.appendChild(badge);

  if (res.issues && res.issues.length) {
    const ul = document.createElement('ul');
    for (const i of res.issues) {
      const li = document.createElement('li');
      li.textContent = i;
      ul.appendChild(li);
    }
    detailsEl.appendChild(ul);
    const explain = document.createElement('div');
    explain.className = 'explain';
    explain.textContent = 'Tip: Review the listed issues; multiple indicators increase risk.';
    detailsEl.appendChild(explain);
  } else if (res.verdict === 'Valid') {
    detailsEl.textContent = 'No common phishing indicators detected.';
  }

  if (res.normalized) {
    const norm = document.createElement('div');
    norm.textContent = 'Normalized: ' + res.normalized;
    metaEl.appendChild(norm);
  }
  if (res.host) {
    const host = document.createElement('div');
    host.textContent = 'Host: ' + res.host;
    metaEl.appendChild(host);
  }
  if (res.category) {
    const cat = document.createElement('div');
    cat.textContent = 'Type: ' + res.category;
    metaEl.appendChild(cat);
  }

  const score = document.createElement('div');
  score.textContent = 'Score: ' + res.score + '/100';
  metaEl.appendChild(score);

  // Guidance text and examples
  guidanceEl.innerHTML = '';
  examplesEl.innerHTML = '';
  const guidanceMap = {
    'Safe': { label: 'Safe to open', advice: 'No common indicators found. Proceed with normal caution.' },
    'Suspicious': { label: 'Be cautious', advice: 'One or two indicators detected — review the details and avoid entering credentials.' },
    'Fake/Scam': { label: 'Do NOT click', advice: 'Multiple indicators suggest phishing or scam. Do not open or enter credentials.' },
    'Invalid': { label: 'Invalid input', advice: 'The provided text could not be parsed as a URL.' }
  };

  const g = guidanceMap[res.verdict] || { label: res.verdict, advice: '' };
  const gTitle = document.createElement('div');
  gTitle.className = 'status-bubble ' + (res.verdict === 'Safe' ? 'valid' : res.verdict === 'Suspicious' ? 'suspicious' : res.verdict === 'Fake/Scam' ? 'dangerous' : 'invalid');
  gTitle.textContent = g.label;
  guidanceEl.appendChild(gTitle);
  const gText = document.createElement('div');
  gText.style.marginTop = '8px';
  gText.textContent = g.advice;
  guidanceEl.appendChild(gText);

  // Example links for user education
  const examples = {
    'Safe': ['https://example.com', 'https://phishield.rlj.com/about'],
    'Suspicious': ['http://login-example.tk/account', 'http://192.0.2.123/verify'],
    'Fake/Scam': ['http://paypal-secure-login-paypal.com', 'http://xn--ppal-4ve.com'],
    'Invalid': ['not a url', 'htp://missing']
  };
  const ex = examples[res.verdict] || [];
  if (ex.length) {
    const exHead = document.createElement('div');
    exHead.style.marginTop = '8px';
    exHead.style.fontSize = '13px';
    exHead.style.color = 'var(--muted)';
    exHead.textContent = 'Example links (click to autofill and scan):';
    examplesEl.appendChild(exHead);
    const wrap = document.createElement('div');
    wrap.className = 'example-list';
    for (const u of ex) {
      const btn = document.createElement('button');
      btn.className = 'example-btn';
      btn.textContent = u;
      btn.onclick = () => {
        const inputEl = document.getElementById('urlInput');
        inputEl.value = u;
        const submit = document.querySelector('#scanForm button[type="submit"]');
        if (submit) submit.click();
        else document.getElementById('scanForm').dispatchEvent(new Event('submit', { cancelable: true }));
      };
      wrap.appendChild(btn);
    }
    examplesEl.appendChild(wrap);
  }

  // Actions
  const actions = document.createElement('div');
  actions.style.marginTop = '10px';
  const copyBtn = document.createElement('button');
  copyBtn.className = 'btn';
  copyBtn.textContent = 'Copy URL';
  copyBtn.onclick = () => navigator.clipboard && navigator.clipboard.writeText(document.getElementById('urlInput').value);

  const openBtn = document.createElement('button');
  openBtn.className = 'btn';
  openBtn.textContent = 'Open (use caution)';
  openBtn.onclick = async () => {
    const url = document.getElementById('urlInput').value;
    if (!url) return;
    const host = res.host || (() => { try { return (new URL(url)).hostname } catch(e){ return '' } })();
    if (res.verdict === 'Suspicious' || res.verdict === 'Fake/Scam') {
      const ok = await requireConfirmation(host);
      if (!ok) return alert('Proceed canceled.');
    } else {
      // minor confirmation for all non-safe categories could be added here
    }
    window.open(url, '_blank', 'noopener');
  };

  const reportBtn = document.createElement('button');
  reportBtn.className = 'btn';
  reportBtn.textContent = 'Report';
  reportBtn.onclick = () => {
    const reportUrl = document.getElementById('urlInput').value || document.getElementById('meta')?.dataset?.scannedUrl || '';
    if (!reportUrl) return alert('No URL to report.');
    const payload = { url: reportUrl, reason: 'reported from UI' };
    fetch(API_ENDPOINT.replace(/\/api\/scan\/?$/, '/api/report'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      .then(r => r.json()).then(j => {
        if (j && j.ok) alert('Report submitted. Thank you.');
        else alert('Report failed.');
      }).catch(()=>alert('Report failed.'));
  };

  actions.appendChild(copyBtn);
  actions.appendChild(openBtn);
  actions.appendChild(reportBtn);
  metaEl.appendChild(actions);
}

// Confirmation modal helper: returns a Promise that resolves true if user confirms, false otherwise.
function requireConfirmation(expectedDomain) {
  return new Promise((resolve) => {
    const modal = document.getElementById('confirmModal');
    const input = document.getElementById('confirmInput');
    const msg = document.getElementById('confirmMsg');
    const proceed = document.getElementById('confirmProceed');
    const cancel = document.getElementById('confirmCancel');
    if (!modal || !input || !proceed || !cancel) return resolve(false);
    modal.style.display = 'flex';
    input.value = '';
    msg.textContent = 'This site was flagged as risky. To proceed, type the domain name exactly: ' + expectedDomain;
    const onInput = () => {
      proceed.disabled = (input.value.trim() !== expectedDomain);
    };
    const cleanup = () => {
      input.removeEventListener('input', onInput);
      proceed.removeEventListener('click', onProceed);
      cancel.removeEventListener('click', onCancel);
      modal.style.display = 'none';
    };
    const onProceed = () => { cleanup(); resolve(true); };
    const onCancel = () => { cleanup(); resolve(false); };
    input.addEventListener('input', onInput);
    proceed.addEventListener('click', onProceed);
    cancel.addEventListener('click', onCancel);
    // focus input
    setTimeout(() => input.focus(), 50);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scanForm');
  const input = document.getElementById('urlInput');
  const clear = document.getElementById('clearBtn');

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const val = input.value.trim();
    const res = analyzeURL(val);
    renderResult(res);

    // render confidence meter
    const conf = document.getElementById('confidence');
    conf.innerHTML = '';
    const meter = document.createElement('div'); meter.className = 'meter'; const bar = document.createElement('i'); bar.style.width = (res.score) + '%'; meter.appendChild(bar); conf.appendChild(meter);

    // category chip
    const oneclick = document.getElementById('oneclick'); oneclick.innerHTML = '';
    const chip = document.createElement('span'); chip.className='chip'; chip.textContent = res.category || 'Other'; oneclick.appendChild(chip);
    const isolated = document.createElement('button'); isolated.className='btn'; isolated.textContent='Open isolated'; isolated.style.marginLeft='8px';
    isolated.onclick = () => { window.open(val, '_blank', 'noopener,noreferrer'); };
    oneclick.appendChild(isolated);
    const sandboxBtn = document.createElement('button'); sandboxBtn.className='btn'; sandboxBtn.textContent='Sandbox Preview'; sandboxBtn.style.marginLeft='8px';
    sandboxBtn.onclick = () => {
      const s = JSON.parse(localStorage.getItem('ph_settings')||'{}');
      const api = s.api || API_ENDPOINT;
      if (!api) return alert('No API endpoint configured for sandbox');
      fetch(api.replace(/\/api\/scan\/?$/, '/api/sandbox'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: val }) })
        .then(r=>r.json()).then(j=> showSandboxResult(j)).catch(()=> alert('Sandbox request failed'));
    };
    oneclick.appendChild(sandboxBtn);

    // Push to history
    pushHistory({ url: val, verdict: res.verdict, score: res.score, category: res.category || 'Other', ts: Date.now() });

    // optional server-side scan (if a server proxy is available)
    fetch(API_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: val })
    }).then(r => r.json()).then(j => {
      if (!j) return;
      const metaEl = document.getElementById('meta');
      const srv = document.createElement('div');
      srv.style.marginTop = '8px';
      srv.style.fontSize = '13px';
      srv.style.color = 'var(--muted)';
      if (j.provider === 'aggregator') {
        srv.innerHTML = '<strong>Server scan summary:</strong> ' + (j.verdicts && j.verdicts.length ? j.verdicts.join(', ') : 'no issues');
        const det = document.createElement('pre');
        det.style.marginTop = '8px';
        det.style.whiteSpace = 'pre-wrap';
        det.style.fontSize = '12px';
        det.style.color = 'var(--muted)';
        det.textContent = JSON.stringify(j.details, null, 2);
        srv.appendChild(det);
      } else {
        srv.textContent = 'Server scan: ' + (j.provider || '') + ' — ' + (j.verdict || j.message || JSON.stringify(j));
      }
      metaEl.appendChild(srv);
    }).catch(()=>{});
  });

  clear.addEventListener('click', () => {
    input.value = '';
    document.getElementById('verdict').textContent = 'No scan yet';
    document.getElementById('details').innerHTML = '';
    document.getElementById('meta').innerHTML = '';
  });

  // Settings modal wiring
  const settingsBtn = document.createElement('button');
  settingsBtn.className = 'btn';
  settingsBtn.textContent = 'Settings';
  settingsBtn.style.marginLeft = '8px';
  document.querySelector('.actions').appendChild(settingsBtn);
  const settingsModal = document.getElementById('settingsModal');
  const settingsClose = document.getElementById('settingsClose');
  const settingsSave = document.getElementById('settingsSave');
  const settingsApi = document.getElementById('settingsApi');
  const settingsSandbox = document.getElementById('settingsSandbox');
  const settingsStrictConfirm = document.getElementById('settingsStrictConfirm');

  function loadSettings() {
    const s = JSON.parse(localStorage.getItem('ph_settings') || '{}');
    settingsApi.value = s.api || API_ENDPOINT || '';
    settingsSandbox.checked = !!s.sandbox;
    settingsStrictConfirm.checked = !!s.strictConfirm;
  }
  function saveSettings() {
    const s = { api: settingsApi.value.trim(), sandbox: settingsSandbox.checked, strictConfirm: settingsStrictConfirm.checked };
    localStorage.setItem('ph_settings', JSON.stringify(s));
    if (s.api) API_ENDPOINT = s.api;
  }
  settingsBtn.addEventListener('click', () => { loadSettings(); settingsModal.style.display = 'flex'; });
  settingsClose.addEventListener('click', () => settingsModal.style.display = 'none');
  settingsSave.addEventListener('click', () => { saveSettings(); settingsModal.style.display = 'none'; alert('Settings saved'); });

  // Scan history
  const historyLimit = 50;
  function loadHistory() { return JSON.parse(localStorage.getItem('ph_history') || '[]'); }
  function saveHistory(h) { localStorage.setItem('ph_history', JSON.stringify(h.slice(0, historyLimit))); }
  function pushHistory(entry) {
    const h = loadHistory();
    h.unshift(entry);
    saveHistory(h);
    renderHistory();
  }
  function clearHistory() { localStorage.removeItem('ph_history'); renderHistory(); }
  function renderHistory() {
    let wrap = document.getElementById('historyWrap');
    if (!wrap) {
      wrap = document.createElement('div'); wrap.id = 'historyWrap'; wrap.className = 'history';
      document.getElementById('result').appendChild(wrap);
    }
    const h = loadHistory();
    wrap.innerHTML = '';
    for (const it of h) {
      const row = document.createElement('div'); row.className = 'history-item';
      const left = document.createElement('div'); left.innerHTML = '<strong>' + it.url + '</strong><div class="meta">' + it.verdict + ' • ' + it.score + '/100 • ' + it.category + ' • ' + new Date(it.ts).toLocaleString() + '</div>';
      const actions = document.createElement('div');
      const rescan = document.createElement('button'); rescan.className='small-btn'; rescan.textContent='Rescan'; rescan.onclick = () => { document.getElementById('urlInput').value = it.url; document.querySelector('#scanForm button[type="submit"]').click(); };
      const remove = document.createElement('button'); remove.className='small-btn'; remove.textContent='Remove'; remove.onclick = () => { const arr = loadHistory().filter(x=>x.ts!==it.ts); saveHistory(arr); renderHistory(); };
      actions.appendChild(rescan); actions.appendChild(remove);
      row.appendChild(left); row.appendChild(actions); wrap.appendChild(row);
    }
  }

  document.getElementById('clearHistoryBtn').addEventListener('click', () => { if (confirm('Clear scan history?')) { clearHistory(); } });

  // Export JSON
  document.getElementById('exportBtn').addEventListener('click', () => {
    const h = loadHistory();
    const blob = new Blob([JSON.stringify(h, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'phishield-history.json'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  });

  renderHistory();

  // Sandbox preview trigger
  const sandboxPreview = document.getElementById('sandboxPreview');
  function showSandboxResult(obj) {
    sandboxPreview.innerHTML = '<strong>Sandbox result:</strong><pre style="white-space:pre-wrap;color:var(--muted);font-size:12px">' + JSON.stringify(obj, null, 2) + '</pre>';
  }


  // Info modal handlers
  const guidelinesBtn = document.getElementById('guidelinesBtn');
  const aboutBtn = document.getElementById('aboutBtn');
  const infoModal = document.getElementById('infoModal');
  const infoBody = document.getElementById('infoBody');
  const infoTitle = document.getElementById('infoTitle');
  const infoClose = document.getElementById('infoClose');
  const guidelinesTpl = document.getElementById('guidelinesTpl');
  const aboutTpl = document.getElementById('aboutTpl');

  function openInfo(title, html) {
    infoTitle.textContent = title;
    infoBody.innerHTML = html;
    infoModal.style.display = 'flex';
  }

  if (guidelinesBtn && guidelinesTpl) {
    guidelinesBtn.addEventListener('click', () => openInfo('Guidelines', guidelinesTpl.innerHTML));
  }
  if (aboutBtn && aboutTpl) {
    aboutBtn.addEventListener('click', () => openInfo('About Phishield', aboutTpl.innerHTML));
  }
  if (infoClose) infoClose.addEventListener('click', () => { infoModal.style.display = 'none'; });
  infoModal.addEventListener('click', (e) => { if (e.target === infoModal) infoModal.style.display = 'none'; });

  // Keyboard shortcuts: Ctrl/Cmd+G = Guidelines, Ctrl/Cmd+I = About
  document.addEventListener('keydown', (e) => {
    const active = document.activeElement;
    const tag = active && active.tagName ? active.tagName.toLowerCase() : '';
    if (tag === 'input' || tag === 'textarea' || (active && active.isContentEditable)) return;
    const isCmd = e.ctrlKey || e.metaKey;
    if (!isCmd) return;
    if (e.key && e.key.toLowerCase() === 'g') {
      e.preventDefault();
      if (guidelinesTpl) openInfo('Guidelines', guidelinesTpl.innerHTML);
    }
    if (e.key && e.key.toLowerCase() === 'i') {
      e.preventDefault();
      if (aboutTpl) openInfo('About Phishield', aboutTpl.innerHTML);
    }
  });
  // Founder modal wiring
  const founderBtn = document.getElementById('founderBtn');
  const founderModal = document.getElementById('founderModal');
  const founderClose = document.getElementById('founderClose');
  if (founderBtn && founderModal) founderBtn.addEventListener('click', () => { founderModal.style.display = 'flex'; });
  if (founderClose) founderClose.addEventListener('click', () => { founderModal.style.display = 'none'; });
  if (founderModal) founderModal.addEventListener('click', (e) => { if (e.target === founderModal) founderModal.style.display = 'none'; });
});
