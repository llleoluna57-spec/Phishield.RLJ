# Phishield — Anti‑Phishing Scanner (Demo)

Phishield is a small client-side demo that scans URLs for common phishing indicators. It runs fully in the browser and does not submit URLs to external services.

## Quick local start

1. Open PowerShell in `c:\Users\Leo Luna\OneDrive\Desktop\My_Website 0.1`
2. Run:
   ```powershell
   .\run.ps1
   ```
3. Open the app in your browser:
   ```text
   http://localhost:3000
   ```

If `run.ps1` cannot find Node/npm, install Node.js from https://nodejs.org/ or run:

```powershell
winget install OpenJS.NodeJS
```

If you want to run manually instead:

```powershell
& 'C:\Program Files\nodejs\npm.cmd' install
& 'C:\Program Files\nodejs\node.exe' server.js
```

Files:

- [index.html](index.html) — main UI
- [style.css](style.css) — styles
- [script.js](script.js) — scanner logic
- [logo.svg](logo.svg) — RLJ logo

How to use

1. Open `index.html` in any modern browser or serve the folder locally:

```bash
python -m http.server 8000
# then open http://localhost:8000
```

2. Enter a URL or domain and press **Scan**.
3. Review the verdict, issues list, and score. Use **Open (use caution)** only if you trust the site.

Verdict categories

- **Safe** — No common phishing indicators found.
- **Suspicious** — One or two indicators detected; exercise caution.
- **Fake/Scam** — Multiple indicators strongly suggest phishing or scam.
- **Invalid** — Input couldn't be parsed as a URL.

Detection rules & guidance

- Fake: Lookalike domains using typos, visual homographs (punycode), extra subdomains, or small edits to brand names.
- Scam: IP-address hosts, long obfuscated URLs, credential redirects (contains '@'), or URLs with urgent phishing words ("verify", "update").
- Not proper/Unsafe: Missing HTTPS, uncommon risky TLDs (.tk, .ml, .zip), or very long hostnames and query strings.

Best practices

- Do not enter credentials on sites you reached via unknown links.
- When unsure, go to the service's homepage from a known bookmark or search engine instead of following the link.
- Verify unexpected messages by contacting the sender through a separate channel.

Limitations

- This tool is a client-side heuristic demo and not a substitute for production threat intelligence or endpoint protection.
- Heuristics can produce false positives or false negatives; combine with other signals.

Next steps (optional enhancements)

- Integrate server-side reputation APIs (VirusTotal, Google Safe Browsing) for better coverage.
- Add a blocklist/allowlist and exportable reports.
- Build as a PWA or browser extension to protect browsing in real-time.

Optional server proxy (recommended for stronger checks)

You can run a small Node.js proxy that queries Google Safe Browsing and returns a simple verdict. This improves detection beyond client-side heuristics.

1. Create a project folder (this repo already contains `server.js` and `package.json`).
2. Install dependencies:

```bash
npm install
```

3. Set the Google Safe Browsing API key (obtain from Google Cloud Console) and run:

```bash
export GSB_API_KEY="YOUR_KEY"
npm start
```

4. When the server runs on the same host as the site, the client will automatically POST to `/api/scan` and display server results.

Security note

- Do not commit API keys to source control. Use environment variables on the server.
- The server proxy is optional; the client works offline with heuristics but server checks significantly reduce false negatives.

Additional server features

- The proxy can combine multiple providers and checks:
	- Google Safe Browsing (set `GSB_API_KEY`)
	- VirusTotal URL analysis (set `VT_API_KEY`)
	- TLS / certificate checks (expiry, host mismatch, HSTS)
	- WHOIS / domain age checks (flags very new domains)

ML / Heuristics ensemble

- The server now computes an ensemble score that combines blocklist/GSB/VirusTotal hits, TLS issues, WHOIS age, domain entropy, lookalike distance, and phishing keywords into a single `ensemble` object in the JSON response: `{ score, verdict, entropy }`.
- `score` ranges 0-100; verdict is `Safe`, `Suspicious`, or `Fake/Scam`.

 Sandbox rendering (advanced)
 
 Reporting (crowdsourced)
 
 - Users can report suspicious links via the web UI or extension popup. The server exposes `POST /api/report` to accept `{ url, reason, reporter }` and stores reports in `reports.json`.
 - For demo purposes `GET /api/reports` returns all reports; in production protect this endpoint and implement moderation workflows.

- The server exposes an optional `/api/sandbox` endpoint that uses a headless Chromium (Puppeteer) to render the page in a controlled environment and report behavior indicators such as navigation redirects, presence of password fields, external script domains, inline eval usage, and meta-refresh tags.
- Sandbox is resource-intensive and should be enabled on a server with adequate CPU/RAM. It runs pages for a short time and times out if slow. Use with caution — do not run untrusted code on your management host without proper isolation (Docker, separate VM, or container security flags like `--no-sandbox` are used but are not foolproof).



When enabled, the server returns an aggregated JSON with `verdicts` and `details` that the client displays under the scan results.

To enable VirusTotal checks, set `VT_API_KEY` and restart the server. Note that VirusTotal may rate-limit API usage.

Deploying the website and server (quick guide)

1) Static site (frontend) — GitHub Pages (free)

- Create a GitHub repository and push the project files (keep `server.js` and server files on a separate branch if you prefer).
- In the repo Settings → Pages, set the source to the `main` branch (root) or use the `gh-pages` branch.
- After a few minutes your static site will be available at `https://<your-username>.github.io/<repo>`.

2) Server proxy (backend) — Render / Railway / any Docker host

- Option A: Render (quick): Create a new Web Service, connect your GitHub repo, set the start command `npm start`, and add environment variables `GSB_API_KEY` and `VT_API_KEY` in service settings. Render provides a public URL you can use from the frontend.
- Option B: Deploy using Docker (any host with Docker): build and run the image:

```bash
docker build -t phishield-server .
docker run -e GSB_API_KEY="$GSB" -e VT_API_KEY="$VT" -p 3000:3000 phishield-server
```

3) Configure the frontend to call your server

- If you host the frontend separately, update the client fetch path in `script.js` from `/api/scan` to your server URL, e.g. `https://phishield-server.example.com/api/scan`.

Privacy & security

- Keep API keys secret; use the hosting provider's environment variables feature.
- When the server is public, enable rate-limiting and logging on the host to avoid abuse.

Runtime override (Option A)

If you prefer to set the server URL at runtime (without rebuilding), add a small script before `script.js` in `index.html` to set the endpoint:

```html
<script>
	// Replace with your deployed server's API endpoint
	window.__PHISHIELD_API_URL__ = "https://phishield-server.example.com/api/scan";
</script>
<script src="script.js"></script>
```

This is useful for testing or when frontend and backend are deployed to separate hosts.


Guidance & examples

- If the verdict shows **"Do NOT click"** or **"Fake/Scam"**, do not open the link. Examples: `http://paypal-secure-login-paypal.com`, `http://xn--ppal-4ve.com`.
- If it shows **"Be cautious"** or **"Suspicious"**, review the issues list — avoid entering credentials and verify the sender.
- If it shows **"Safe"**, the link shows no common indicators; still follow normal web safety practices.

Example educational links by verdict:

- Safe: `https://example.com`, `https://phishield.rlj.com/about`
- Suspicious: `http://login-example.tk/account`, `http://192.0.2.123/verify`
- Fake/Scam: `http://paypal-secure-login-paypal.com`, `http://xn--ppal-4ve.com`


