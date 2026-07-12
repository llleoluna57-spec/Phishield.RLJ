// Enhanced client-side anti-phishing heuristics for demo purposes.
const suspiciousTLDs = ['tk','ml','ga','cf','gq','zip','review','kim'];
const phishingWords = ['login','secure','account','update','verify','bank','signin','confirm'];
const localBlocklist = ['malicious.example', 'phishingsite.test'];
const officialWhitelist = ['google.com','facebook.com','apple.com','amazon.com','microsoft.com','paypal.com','github.com','linkedin.com','twitter.com','instagram.com'];

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

function isUrlSyntaxValid(raw) {
  if (!raw || typeof raw !== 'string') return false;
  const trimmed = raw.trim();
  if (trimmed.length === 0) return false;

  if (/\s/.test(trimmed)) return false;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    try { new URL(trimmed); return true; } catch (e) { return false; }
  }
  try { new URL('http://' + trimmed); return true; } catch (e) { return false; }
}

function isOfficialDomain(host) {
  return officialWhitelist.some(d => host === d || host.endsWith('.' + d));
}

function hasHiddenRedirect(raw) {
  const normal = raw.toLowerCase();
  return /@/.test(normal) || /[?&](url|redirect|next|destination)=/.test(normal) || /\/redirect\//.test(normal);
}

function analyzeURL(raw) {
  const issues = [];
  const result = {
    verdict: 'INVALID',
    status: 'invalid',
    issues,
    score: 0,
    category: 'Other',
    normalized: raw,
    host: '',
    path: ''
  };

  if (!isUrlSyntaxValid(raw)) {
    issues.push('The input is not a valid URL format.');
    return result;
  }

  let input = raw.trim();
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(input)) {
    input = 'http://' + input;
  }

  try {
    const url = new URL(input);
    result.normalized = url.href;
    result.host = url.hostname;
    result.path = url.pathname + url.search + url.hash;
    const host = url.hostname;
    const parts = host.split('.').filter(Boolean);
    const tld = parts.length ? parts[parts.length - 1].toLowerCase() : '';
    const domainOnly = parts.slice(-2).join('.').toLowerCase();

    if (!parts.length || parts.length < 2) {
      issues.push('Hostname does not contain a valid domain.');
      return result;
    }
    if (localBlocklist.includes(host) || localBlocklist.includes(domainOnly)) {
      issues.push('Domain appears on a known blocklist.');
    }
    if (suspiciousTLDs.includes(tld) && !isOfficialDomain(host)) {
      issues.push('Uses a high-risk top-level domain: .' + tld);
    }
    if (host.includes('xn--')) {
      issues.push('Punycode detected; possible homograph attack.');
    }
    if (hasHiddenRedirect(raw)) {
      issues.push('Hidden redirect pattern detected.');
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
      issues.push('Hostname is an IP address.');
    }
    if (host.includes('-')) {
      issues.push('Hyphen in domain may indicate a lookalike/personalized address.');
    }
    for (const w of phishingWords) {
      if (host.toLowerCase().includes(w) || result.path.toLowerCase().includes(w)) {
        issues.push('Phishing keyword detected: ' + w);
      }
    }
    if (parts.length >= 4) {
      issues.push('Many subdomains present; could be deceptive.');
    }
    if (host.length > 60) {
      issues.push('Hostname is unusually long.');
    }
    if (result.path.length > 200) {
      issues.push('URL is unusually long.');
    }
    const known = ['paypal','google','facebook','microsoft','apple','amazon','bank','github','linkedin','twitter','instagram'];
    const label = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
    for (const k of known) {
      const dist = levenshtein(label.toLowerCase(), k.toLowerCase());
      if (dist > 0 && dist <= 2 && !host.includes(k)) {
        issues.push('Lookalike domain similar to "' + k + '".');
        break;
      }
    }
    if (url.protocol !== 'https:') {
      issues.push('The link does not use HTTPS.');
    }

    const score = Math.max(0, 100 - issues.length * 20);
    result.score = score;
    result.category = classifyURL(url, raw);

    // Determine final classification
    if (issues.length === 0 && url.protocol === 'https:' && isOfficialDomain(host)) {
      result.status = 'valid';
      result.verdict = 'VALID';
    } else if (issues.some(i => i.includes('blocklist') || i.includes('homograph') || i.includes('Hidden redirect') || i.includes('lookalike') || i.includes('Phishing keyword') || i.includes('high-risk'))) {
      result.status = 'dangerous';
      result.verdict = 'DANGEROUS';
    } else if (issues.length > 0) {
      result.status = 'dangerous';
      result.verdict = 'DANGEROUS';
    } else {
      result.status = 'valid';
      result.verdict = 'VALID';
    }

    return result;
  } catch (err) {
    issues.push(err.message);
    return result;
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
  if (res.verdict === 'VALID') cls = 'valid';
  else if (res.verdict === 'DANGEROUS') cls = 'dangerous';
  else cls = 'invalid';
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
  } else if (res.verdict === 'VALID') {
    detailsEl.textContent = 'The link is syntactically valid, secure, and not flagged by heuristics.';
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
  if (examplesEl) examplesEl.innerHTML = '';
  const guidanceMap = {
    'VALID': { label: 'VALID', advice: 'The link looks safe, secure, and belongs to a legitimate domain.' },
    'DANGEROUS': { label: 'DANGEROUS', advice: 'The link appears malicious or deceptive. Do not open it.' },
    'INVALID': { label: 'INVALID', advice: 'The input couldn\'t be parsed or the link appears broken/unreachable.' }
  };

  const g = guidanceMap[res.verdict] || { label: res.verdict, advice: '' };
  const gTitle = document.createElement('div');
  gTitle.className = 'status-bubble ' + (res.verdict === 'VALID' ? 'valid' : res.verdict === 'DANGEROUS' ? 'dangerous' : 'invalid');
  gTitle.textContent = g.label;
  guidanceEl.appendChild(gTitle);
  const gText = document.createElement('div');
  gText.style.marginTop = '8px';
  gText.textContent = g.advice;
  guidanceEl.appendChild(gText);

  // Example links removed per request
  if (examplesEl) examplesEl.innerHTML = '';

  // Actions
  const actions = document.createElement('div');
  actions.style.marginTop = '10px';
  const copyBtn = document.createElement('button');
  copyBtn.className = 'btn';
  copyBtn.textContent = 'Copy URL';
  copyBtn.onclick = () => navigator.clipboard && navigator.clipboard.writeText(document.getElementById('urlInput').value);

  const openBtn = document.createElement('button');
  openBtn.className = 'btn';
  openBtn.textContent = 'Open Directly (use caution)';
  openBtn.onclick = async () => {
    const url = document.getElementById('urlInput').value;
    if (!url) return;
    const host = res.host || (() => { try { return (new URL(url)).hostname } catch(e){ return '' } })();
    if (res.verdict === 'DANGEROUS') {
      const ok = await requireConfirmation(host);
      if (!ok) return alert('Proceed canceled.');
    } else if (res.verdict === 'INVALID') {
      return alert('This link is invalid or broken; do not open it.');
    }
    window.open(url, '_blank', 'noopener');
  };

  const sandboxOpenBtn = document.createElement('button');
  sandboxOpenBtn.className = 'btn';
  sandboxOpenBtn.textContent = 'Play in Secure Sandbox';
  sandboxOpenBtn.style.marginLeft = '8px';
  sandboxOpenBtn.onclick = async () => {
    const url = document.getElementById('urlInput').value;
    if (!url) return;
    const host = res.host || (() => { try { return (new URL(url)).hostname } catch(e){ return '' } })();
    if (res.verdict === 'INVALID') {
      return alert('This link is invalid or broken; do not open it.');
    }
    if (res.verdict === 'DANGEROUS') {
      const ok = await requireConfirmation(host);
      if (!ok) return alert('Sandbox preview canceled.');
    }
    openLinkInSandbox(url);
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
  actions.appendChild(sandboxOpenBtn);
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
      const securitySummaryEl = document.getElementById('securitySummary');
      if (securitySummaryEl) securitySummaryEl.innerHTML = '';
      const srv = document.createElement('div');
      srv.style.marginTop = '8px';
      srv.style.fontSize = '13px';
      srv.style.color = 'var(--muted)';
      if (j.provider === 'aggregator') {
        const summaryText = j.summary && j.summary.status ? `${j.summary.status} — ${j.summary.reason || ''}` : (j.verdicts && j.verdicts.length ? j.verdicts.join(', ') : 'no issues');
        srv.innerHTML = '<strong>Server scan summary:</strong> ' + summaryText;
        if (j.resolvedUrl && j.resolvedUrl !== val) {
          const resolved = document.createElement('div');
          resolved.style.marginTop = '6px';
          resolved.style.fontSize = '12px';
          resolved.style.color = 'var(--muted)';
          resolved.textContent = `Resolved destination: ${j.resolvedUrl}`;
          srv.appendChild(resolved);
        }
        if (j.ensemble) {
          const ens = document.createElement('div');
          ens.style.marginTop = '6px';
          ens.style.fontSize = '12px';
          ens.style.color = 'var(--muted)';
          ens.textContent = `Ensemble score: ${j.ensemble.score}/100 (${j.ensemble.verdict})`;
          srv.appendChild(ens);
        }
        if (j.details && j.details.heuristic) {
          const heur = document.createElement('div');
          heur.style.marginTop = '6px';
          heur.style.fontSize = '12px';
          heur.style.color = 'var(--muted)';
          heur.textContent = `Heuristic: ${j.details.heuristic.status} — ${j.details.heuristic.reason}`;
          srv.appendChild(heur);
        }
        const det = document.createElement('pre');
        det.style.marginTop = '8px';
        det.style.whiteSpace = 'pre-wrap';
        det.style.fontSize = '12px';
        det.style.color = 'var(--muted)';
        det.textContent = JSON.stringify(j.details, null, 2);
        srv.appendChild(det);

        if (securitySummaryEl) {
          const summaryBlock = document.createElement('div');
          summaryBlock.className = 'security-summary';
          const rows = [];
          const statusLabel = j.summary && j.summary.status ? j.summary.status : 'Unknown';
          rows.push(`<div class="field-row"><span><strong>Security status:</strong> ${statusLabel}</span><span><strong>Reason:</strong> ${j.summary?.reason || 'N/A'}</span></div>`);
          if (j.resolvedUrl && j.resolvedUrl !== val) {
            rows.push(`<div class="field-row"><span><strong>Final destination:</strong> ${j.resolvedUrl}</span><span><strong>Redirected:</strong> Yes</span></div>`);
          } else {
            rows.push(`<div class="field-row"><span><strong>Final destination:</strong> ${val}</span><span><strong>Redirected:</strong> No</span></div>`);
          }
          if (j.details && j.details.virustotal) {
            const vt = j.details.virustotal;
            if (vt.result && vt.result.stats) {
              rows.push(`<div class="field-row"><span><strong>VirusTotal:</strong> ${vt.result.stats.malicious || 0} malicious, ${vt.result.stats.suspicious || 0} suspicious</span><span><strong>Harmless:</strong> ${vt.result.stats.harmless || 0}</span></div>`);
            } else if (vt.error) {
              rows.push(`<div class="field-row"><span><strong>VirusTotal:</strong> unavailable</span><span>${vt.error}</span></div>`);
            }
          }
          summaryBlock.innerHTML = rows.join('');
          securitySummaryEl.appendChild(summaryBlock);
        }
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
    const summary = document.getElementById('securitySummary');
    if (summary) summary.innerHTML = '';
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

  async function checkLinkReachability(url) {
    const api = window.__PHISHIELD_API_URL__ || API_ENDPOINT || '/api/scan';
    const probeEndpoint = api.replace(/\/api\/scan\/?$/, '/api/probe');
    try {
      const response = await fetch(probeEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await response.json();
      if (!response.ok) {
        return { text: `Proxy probe failed: ${data.error || response.statusText}`, reachable: false };
      }
      let text = data.reachable
        ? 'Backend proxy probe: reachable.'
        : 'Backend proxy probe: unreachable.';
      if (data.finalUrl && data.finalUrl !== url) {
        text += ` Resolved destination: ${data.finalUrl}`;
      }
      return { text, reachable: !!data.reachable };
    } catch (err) {
      return { text: 'Backend proxy probe failed. Browser-side reachability cannot be verified.', reachable: false };
    }
  }

  async function openLinkInSandbox(url) {
    const settings = JSON.parse(localStorage.getItem('ph_settings') || '{}');
    const api = settings.api || API_ENDPOINT;
    if (!api) return alert('No sandbox endpoint configured. Please set an API endpoint in Settings.');

    const sandboxEndpoint = api.replace(/\/api\/scan\/?$/, '/api/sandbox');
    const preview = document.getElementById('sandboxPreview');
    if (preview) {
      preview.innerHTML = '<strong>Secure sandbox:</strong> Sending request to sandbox...';
    }

    try {
      const response = await fetch(sandboxEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const json = await response.json();
      if (preview) {
        preview.innerHTML = '<strong>Secure sandbox result:</strong><pre style="white-space:pre-wrap;color:var(--muted);font-size:12px">' + JSON.stringify(json, null, 2) + '</pre>';
      }
    } catch (err) {
      if (preview) {
        preview.innerHTML = '<strong>Secure sandbox failed:</strong> Unable to complete the sandbox request. ' + (err.message || '');
      }
    }
  }

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
