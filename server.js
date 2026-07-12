// Enhanced scan proxy: Google Safe Browsing + optional VirusTotal + WHOIS + TLS checks
// Usage: set GSB_API_KEY and/or VT_API_KEY and run `node server.js`

const express = require('express');
const fetch = require('node-fetch');
const bodyParser = require('body-parser');
const whois = require('whois-json');
const tls = require('tls');
const https = require('https');
const { URL } = require('url');

const app = express();
const port = process.env.PORT || 3000;

const fs = require('fs');
const path = require('path');
const puppeteer = require('puppeteer');

async function resolveRedirects(url) {
  try {
    const response = await fetch(url, { method: 'HEAD', redirect: 'follow', timeout: 5000 });
    if (response && response.url) return response.url;
    const fallback = await fetch(url, { method: 'GET', redirect: 'follow', timeout: 7000 });
    return fallback && fallback.url ? fallback.url : null;
  } catch (err) {
    return null;
  }
}

async function backendProbeUrl(url) {
  try {
    let response = await fetch(url, { method: 'HEAD', redirect: 'follow', timeout: 7000 });
    if (response.status === 405 || response.status === 501 || response.status === 403) {
      response = await fetch(url, { method: 'GET', redirect: 'follow', timeout: 10000 });
    }
    const finalUrl = response.url || url;
    const reachable = response.ok || (response.status >= 200 && response.status < 400);
    return {
      originalUrl: url,
      finalUrl,
      redirected: finalUrl !== url,
      reachable,
      status: response.status,
      statusText: response.statusText,
      headers: {
        'content-type': response.headers.get('content-type') || ''
      }
    };
  } catch (err) {
    return {
      originalUrl: url,
      finalUrl: url,
      redirected: false,
      reachable: false,
      error: err.message || 'Probe request failed.'
    };
  }
}

// Blocklist management
let blocklist = new Set();
let blocklistUpdated = null;
const BLOCKLIST_FILE = 'blocklist.json';
const defaultSources = [
  // Example sources (replace with preferred curated lists)
  'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-clean-shrunk-master/phishing-domains-ACTIVE-2020-09-19.txt'
];
const sources = (process.env.BLOCKLIST_SOURCES && process.env.BLOCKLIST_SOURCES.split(',')) || defaultSources;

async function fetchBlocklistOnce() {
  try {
    const newSet = new Set();
    for (const s of sources) {
      try {
        const r = await fetch(s.trim());
        if (!r.ok) continue;
        const txt = await r.text();
        for (const line of txt.split(/\r?\n/)) {
          const l = line.trim();
          if (!l) continue;
          // simple parsing: extract domain-like tokens
          const token = l.split(/[\s,#\/]/)[0];
          // remove protocol if present
          const only = token.replace(/^https?:\/\//i, '').replace(/^www\./i, '');
          if (only) newSet.add(only.toLowerCase());
        }
      } catch (e) {
        console.error('blocklist source fetch failed', s, e.message);
      }
    }
    blocklist = newSet;
    blocklistUpdated = new Date().toISOString();
    // persist to disk
    try { fs.writeFileSync(BLOCKLIST_FILE, JSON.stringify({ updated: blocklistUpdated, domains: Array.from(blocklist) }, null, 2)); } catch (e) {}
    console.log('Blocklist updated, entries:', blocklist.size);
  } catch (err) {
    console.error('fetchBlocklistOnce error', err.message);
  }
}

// load from disk if present
try {
  if (fs.existsSync(BLOCKLIST_FILE)) {
    const raw = fs.readFileSync(BLOCKLIST_FILE, 'utf8');
    const obj = JSON.parse(raw);
    if (obj && obj.domains) { blocklist = new Set(obj.domains); blocklistUpdated = obj.updated || null; }
  }
} catch (e) { console.error('failed reading blocklist file', e.message); }

// schedule periodic updates every 6 hours
fetchBlocklistOnce();
setInterval(fetchBlocklistOnce, parseInt(process.env.BLOCKLIST_INTERVAL_MS || String(6 * 60 * 60 * 1000), 10));

app.use(bodyParser.json());

// Serve static files from the current directory (UI). This makes the server
// provide the website and the API from the same origin so `node server.js`
// is sufficient to run the full app at http://localhost:PORT
app.use(express.static(path.join(__dirname)));
// SPA fallback to index.html for unknown GET routes
app.get('*', (req, res, next) => {
  if (req.method !== 'GET' || req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

async function gsbCheck(url) {
  if (!process.env.GSB_API_KEY) return { available: false };
  const apiKey = process.env.GSB_API_KEY;
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const body = {
    client: { clientId: 'phishield', clientVersion: '1.0' },
    threatInfo: {
      threatTypes: [ 'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION' ],
      platformTypes: [ 'ANY_PLATFORM' ],
      threatEntryTypes: [ 'URL' ],
      threatEntries: [ { url } ]
    }
  };
  try {
    const r = await fetch(endpoint, { method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' } });
    const j = await r.json();
    return { available: true, result: j };
  } catch (err) {
    return { available: true, error: err.message };
  }
}

async function virusTotalCheck(url) {
  if (!process.env.VT_API_KEY) return { available: false };
  const key = process.env.VT_API_KEY;
  try {
    const params = new URLSearchParams();
    params.append('url', url);
    const post = await fetch('https://www.virustotal.com/api/v3/urls', { method: 'POST', body: params, headers: { 'x-apikey': key } });
    const postJson = await post.json();
    const analysisId = postJson && postJson.data && postJson.data.id;
    if (!analysisId) return { available: true, error: 'no_analysis_id' };
    // Poll analysis
    const maxMs = 8000; const start = Date.now();
    while (Date.now() - start < maxMs) {
      const a = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers: { 'x-apikey': key } });
      const aj = await a.json();
      if (aj && aj.data && aj.data.attributes && aj.data.attributes.status === 'completed') {
        return { available: true, result: aj.data.attributes };
      }
      await new Promise(r => setTimeout(r, 1000));
    }
    return { available: true, error: 'timeout' };
  } catch (err) {
    return { available: true, error: err.message };
  }
}

function checkTLS(host, port = 443, timeout = 5000) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      try {
        const cert = socket.getPeerCertificate(true) || {};
        const subject = cert.subject || {};
        const valid_from = cert.valid_from || null;
        const valid_to = cert.valid_to || null;
        const now = new Date();
        const expires = valid_to ? new Date(valid_to) : null;
        const expired = expires ? expires < now : false;
        const san = cert.subjectAltName || '';
        const matchesHost = (san && san.includes(host)) || (subject.CN && subject.CN === host);
        socket.end();
        // HSTS check
        const req = https.request({ host, method: 'HEAD', port: 443, path: '/', timeout: 3000 }, (res) => {
          const hsts = !!res.headers['strict-transport-security'];
          resolve({ cert: { subject, valid_from, valid_to, expired, san }, matchesHost, hsts });
        });
        req.on('error', () => resolve({ cert: { subject, valid_from, valid_to, expired, san }, matchesHost, hsts: false }));
        req.end();
      } catch (e) {
        socket.end();
        resolve({ error: e.message });
      }
    });
    socket.setTimeout(timeout, () => { socket.destroy(); resolve({ error: 'tls_timeout' }); });
    socket.on('error', (err) => resolve({ error: err.message }));
  });
}

async function whoisCheck(host) {
  try {
    const info = await whois(host, { follow: 3 });
    // attempt to find creation date
    const raw = info;
    const candidates = ['creationDate','created','createdDate','Creation Date','registered','registeredDate'];
    let created = null;
    for (const k of candidates) {
      if (raw[k]) { created = raw[k]; break; }
    }
    // fallback: try raw['domainCreationDate'] or parse from raw
    if (!created) {
      for (const v of Object.values(raw)) {
        if (typeof v === 'string' && /\d{4}-\d{2}-\d{2}/.test(v)) { created = v; break; }
      }
    }
    let ageDays = null;
    if (created) {
      const d = new Date(created);
      if (!isNaN(d)) ageDays = Math.floor((Date.now() - d.getTime()) / (1000*60*60*24));
    }
    return { info: raw, created, ageDays };
  } catch (err) {
    return { error: err.message };
  }
}

function isOfficialDomain(host) {
  const official = ['google.com','facebook.com','apple.com','amazon.com','microsoft.com','paypal.com','github.com','linkedin.com','twitter.com','instagram.com'];
  return official.some(d => host === d || host.endsWith('.' + d));
}

function heuristicScan(url, parsed) {
  const host = (parsed.hostname || '').toLowerCase();
  const path = (parsed.pathname || '') + (parsed.search || '') + (parsed.hash || '');
  const issues = [];
  const lowerUrl = url.toLowerCase();
  const suspiciousWords = ['login','secure','account','update','verify','bank','signin','confirm','password','mail','reset','auth'];
  const suspiciousPatterns = ['0','1','vv','rn','paypa','googl','faceb','micros','apple','amaz0n'];
  const parts = host.split('.').filter(Boolean);
  const subdomainCount = Math.max(0, parts.length - 2);

  if (host.includes('xn--')) issues.push('Punycode detected.');
  if (/[?&](url|redirect|next|destination)=/.test(lowerUrl)) issues.push('Hidden redirect parameter detected.');
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) issues.push('IP address used instead of a normal hostname.');
  if (subdomainCount > 3) issues.push('Many subdomains present; may be deceptive.');
  if (url.length > 120) issues.push('Very long URL; often used for phishing.');
  if (host.includes('-') && !isOfficialDomain(host)) issues.push('Hyphenated hostname may be lookalike or suspicious.');
  suspiciousWords.forEach(word => {
    if (host.includes(word) || path.toLowerCase().includes(word)) issues.push('Phishing keyword detected: ' + word + '.');
  });
  if (!isOfficialDomain(host)) {
    for (const token of suspiciousPatterns) {
      if (host.includes(token)) {
        issues.push('Potential lookalike pattern detected: ' + token + '.');
        break;
      }
    }
  }

  if (issues.length === 0) {
    return { status: 'SAFE', reason: 'No structural anomalies detected.', issues };
  }

  const dangerousSignals = issues.some(issue => /Punycode|IP address|Hidden redirect|lookalike|phishing keyword/i.test(issue));
  return {
    status: dangerousSignals ? 'DANGEROUS' : 'SUSPICIOUS',
    reason: issues.join(' '),
    issues
  };
}

function computeOverallStatus(results, host, path) {
  const heuristic = results.heuristic || { status: 'SAFE', reason: 'No structural issues detected.' };
  const gsbDanger = results.gsb && results.gsb.result && results.gsb.result.matches;
  const vtDanger = results.virustotal && results.virustotal.result && results.virustotal.result.stats && results.virustotal.result.stats.malicious > 0;
  const blocked = !!results.blocklist;
  const tlsExpired = results.tls && results.tls.cert && results.tls.cert.expired;
  const youngDomain = results.whois && typeof results.whois.ageDays === 'number' && results.whois.ageDays < 30;

  if (gsbDanger) return { status: 'DANGEROUS', reason: 'Flagged by Google Safe Browsing.' };
  if (vtDanger) return { status: 'DANGEROUS', reason: 'Detected as malicious by VirusTotal.' };
  if (blocked) return { status: 'DANGEROUS', reason: 'Found on an active blocklist.' };
  if (heuristic.status === 'DANGEROUS') return { status: 'DANGEROUS', reason: heuristic.reason };
  if (heuristic.status === 'SUSPICIOUS') return { status: 'SUSPICIOUS', reason: heuristic.reason };
  if (tlsExpired) return { status: 'SUSPICIOUS', reason: 'TLS certificate expired or invalid.' };
  if (youngDomain) return { status: 'SUSPICIOUS', reason: 'Recently registered domain.' };
  return { status: 'SAFE', reason: 'No major threats detected.' };
}

  function charEntropy(s) {
    const counts = {};
    for (const ch of s) counts[ch] = (counts[ch] || 0) + 1;
    const len = s.length || 1;
    let ent = 0;
    for (const k in counts) {
      const p = counts[k] / len;
      ent -= p * Math.log2(p);
    }
    return ent; // bits per symbol
  }

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m+1 }, () => new Array(n+1).fill(0));
    for (let i=0;i<=m;i++) dp[i][0]=i;
    for (let j=0;j<=n;j++) dp[0][j]=j;
    for (let i=1;i<=m;i++) for (let j=1;j<=n;j++) dp[i][j] = Math.min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1] + (a[i-1]===b[j-1]?0:1));
    return dp[m][n];
  }

  function ensembleScore({ results, host, path }) {
    let score = 50;
    if (results.gsb && results.gsb.result && results.gsb.result.matches) score -= 40;
    if (results.virustotal && results.virustotal.result && results.virustotal.result.stats && results.virustotal.result.stats.malicious > 0) score -= 40;
    if (results.blocklist) score -= 50;
    if (results.tls && results.tls.cert) {
      if (results.tls.cert.expired) score -= 20;
      if (!results.tls.matchesHost) score -= 15;
      if (results.tls.hsts) score += 5;
    } else if (results.tls && results.tls.error) {
      score -= 10;
    }
    if (results.whois && results.whois.ageDays !== null) {
      if (results.whois.ageDays < 30) score -= 15;
      else if (results.whois.ageDays > 365) score += 8;
    }
    const ent = charEntropy(host);
    if (ent > 3.5) score -= 15; else score += 2;
    const known = ['paypal','google','facebook','microsoft','apple','amazon','bank'];
    const parts = host.split('.').filter(Boolean);
    const label = parts.length ? parts[parts.length-2] || parts[0] : host;
    for (const k of known) {
      const d = levenshtein(label.toLowerCase(), k.toLowerCase());
      if (d > 0 && d <= 2) score -= 18;
    }
    const p = (path || '').toLowerCase();
    const phishingWords = ['login','secure','account','update','verify','bank','signin','confirm'];
    for (const w of phishingWords) if (p.includes(w)) score -= 8;
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    let verdict = 'Safe';
    if (score < 35) verdict = 'Fake/Scam';
    else if (score < 65) verdict = 'Suspicious';
    return { score: Math.round(score), verdict, entropy: ent };
  }

app.post('/api/scan', async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'missing url' });

  const originalUrl = url;
  let finalUrl = originalUrl;
  let redirected = false;
  let redirectError = null;

  try {
    const resolved = await resolveRedirects(originalUrl);
    if (resolved && resolved !== originalUrl) {
      finalUrl = resolved;
      redirected = true;
    }
  } catch (err) {
    redirectError = err.message || 'redirect resolution failed';
  }

  let parsed;
  try { parsed = new URL(finalUrl); } catch (e) { return res.status(400).json({ error: 'invalid_url', message: e.message }); }
  const host = parsed.hostname;

  const results = {};
  // GSB
  try { results.gsb = await gsbCheck(finalUrl); } catch (e) { results.gsb = { error: e.message }; }
  // VirusTotal
  try { results.virustotal = await virusTotalCheck(finalUrl); } catch (e) { results.virustotal = { error: e.message }; }
  // TLS / cert
  try { results.tls = await checkTLS(host, parsed.port || 443); } catch (e) { results.tls = { error: e.message }; }
  // WHOIS
  try { results.whois = await whoisCheck(host); } catch (e) { results.whois = { error: e.message }; }

  // Aggregate simple verdict
  const verdicts = [];
  // blocklist check
  try {
    if (blocklist.has(host.toLowerCase())) { verdicts.push('blocklist'); results.blocklist = true; } else { results.blocklist = false; }
  } catch (e) {}

  results.originalUrl = originalUrl;
  results.finalUrl = finalUrl;
  results.redirected = redirected;
  if (redirectError) results.redirectError = redirectError;
  results.heuristic = heuristicScan(finalUrl, parsed);
  if (results.gsb && results.gsb.result && results.gsb.result.matches) verdicts.push('gsb_malicious');
  if (results.virustotal && results.virustotal.result && results.virustotal.result.stats && results.virustotal.result.stats.malicious > 0) verdicts.push('vt_malicious');
  if (results.tls && results.tls.cert && results.tls.cert.expired) verdicts.push('tls_expired');
  if (results.whois && results.whois.ageDays !== null && results.whois.ageDays < 30) verdicts.push('young_domain');
  if (results.heuristic && results.heuristic.status === 'DANGEROUS') verdicts.push('heuristic_dangerous');
  if (results.heuristic && results.heuristic.status === 'SUSPICIOUS') verdicts.push('heuristic_suspicious');

  // ensemble scoring
  try {
    const ensemble = ensembleScore({ results, host, path: parsed.pathname + parsed.search + parsed.hash });
    const summary = computeOverallStatus(results, host, parsed.pathname + parsed.search + parsed.hash);
    return res.json({ provider: 'aggregator', verdicts, ensemble, summary, redirected, resolvedUrl: finalUrl, details: results });
  } catch (e) {
    const summary = computeOverallStatus(results, host, parsed.pathname + parsed.search + parsed.hash);
    return res.json({ provider: 'aggregator', verdicts, summary, redirected, resolvedUrl: finalUrl, details: results });
  }
});

app.post('/api/probe', async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'missing url' });
  let parsed;
  try { parsed = new URL(url); } catch (e) { return res.status(400).json({ error: 'invalid_url', message: e.message }); }

  const probe = await backendProbeUrl(parsed.href);
  return res.json(probe);
});

// Sandbox rendering endpoint - loads the page in a headless browser and reports behavior indicators.
app.post('/api/sandbox', async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'missing url' });
  let browser;
  try {
    browser = await puppeteer.launch({ args: ['--no-sandbox','--disable-setuid-sandbox'], headless: true });
    const page = await browser.newPage();
    page.setDefaultNavigationTimeout(15000);
    const navigations = [];
    page.on('framenavigated', (frame) => { navigations.push(frame.url()); });
    const requests = [];
    page.on('request', (r) => requests.push({ url: r.url(), resourceType: r.resourceType() }));
    const responses = [];
    page.on('response', (r) => responses.push({ url: r.url(), status: r.status() }));

    let redirected = 0;
    page.on('requestfinished', async (r) => {
      try { const resStatus = r.response() && r.response().status(); if (resStatus && [301,302,303,307,308].includes(resStatus)) redirected++; } catch(e){}
    });

    await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 }).catch(()=>{});

    // Extract indicators
    const indicators = await page.evaluate(() => {
      const scripts = Array.from(document.scripts || []).map(s => ({ src: s.src || null, inline: !s.src, text: s.textContent ? s.textContent.slice(0,200) : '' }));
      const pwd = !!document.querySelector('input[type="password"]');
      const forms = Array.from(document.forms || []).map(f => ({ hasPassword: !!f.querySelector('input[type="password"]'), action: f.action }));
      const metaRefresh = Array.from(document.querySelectorAll('meta[http-equiv]')).filter(m => m.getAttribute('http-equiv') && m.getAttribute('http-equiv').toLowerCase()==='refresh').map(m=>m.getAttribute('content'));
      const inlineEval = scripts.reduce((acc, s) => acc + ((s.text && s.text.match(/\beval\s*\(|document\.write\(|setTimeout\(|setInterval\(/g) || []).length), 0);
      return { scriptsCount: scripts.length, scripts, passwordField: pwd, forms, metaRefresh, inlineEval };
    });

    const externalScriptDomains = Array.from(new Set(requests.filter(r => r.resourceType === 'script' && r.url).map(r => {
      try { const u = new URL(r.url); return u.hostname; } catch(e){ return null; }
    }).filter(Boolean)));

    await browser.close();
    return res.json({ provider: 'sandbox', navigations, redirected, requestsCount: requests.length, responsesCount: responses.length, externalScriptDomains, indicators });
  } catch (err) {
    if (browser) try { await browser.close(); } catch(e){}
    return res.status(500).json({ error: 'sandbox_error', message: err.message });
  }
});

// Crowdsourced reporting
const REPORTS_FILE = 'reports.json';
let reports = [];
try {
  if (fs.existsSync(REPORTS_FILE)) {
    const raw = fs.readFileSync(REPORTS_FILE, 'utf8');
    reports = JSON.parse(raw) || [];
  }
} catch (e) { console.error('failed reading reports file', e.message); }

function saveReports() {
  try { fs.writeFileSync(REPORTS_FILE, JSON.stringify(reports, null, 2)); } catch (e) { console.error('failed saving reports', e.message); }
}

app.post('/api/report', (req, res) => {
  const { url, reason, reporter } = req.body || {};
  if (!url) return res.status(400).json({ error: 'missing url' });
  const id = (Date.now()).toString(36) + '-' + Math.round(Math.random()*10000);
  const entry = { id, url, reason: reason || 'user_report', reporter: reporter || null, status: 'pending', createdAt: new Date().toISOString() };
  reports.unshift(entry);
  saveReports();
  return res.json({ ok: true, report: entry });
});

// List reports (no auth - for demo only). In production protect this endpoint.
app.get('/api/reports', (req, res) => {
  return res.json({ count: reports.length, updated: blocklistUpdated, reports });
});

app.listen(port, () => console.log('Phishield scan proxy running on port', port));
