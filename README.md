# Recon-Scraper

An authorized-recon web crawler for bug bounty / security engineering work. Crawls a target, extracts assets (links, JS files, forms, params, emails), scans for likely secrets and interesting API endpoints, optionally probes a small set of well-known sensitive paths, and produces a JSON + HTML report.

> **Only run this against targets you own or are explicitly authorized to test** (e.g. an in-scope bug bounty program). The tool prompts for a manual authorization confirmation before it runs unless you pass `-y`.

## Install

```bash
pip install -r requirements.txt
# Optional, only needed for --render:
playwright install chromium
```

## Usage

```bash
python recon-scraper.py -u https://example.com
```

Common options:

```bash
python recon-scraper.py -u https://example.com \
  --depth 3 \                # max crawl depth (default 3)
  --max-pages 300 \          # cap on pages visited (default 300)
  --concurrency 10 \         # concurrent requests (default 10)
  --delay 0.2 \               # seconds between requests per worker, be polite
  --include-subdomains \     # allow crawling *.example.com, not just example.com
  --check-files \            # actively probe .env, .git/config, backups, etc
  --render \                 # headless-browser render for SPAs (React/Vue/Angular)
  --screenshots \            # save full-page screenshots when --render is used
  --no-robots \              # ignore robots.txt (only if your authorization allows it)
  -y                         # skip the interactive authorization prompt
```

Full flag list: `python recon-scraper.py --help`

## Output

```text
[+] Internal URLs: 132
[+] JavaScript Files: 24
[+] API Endpoints: 53
[+] Forms: 7
[+] Emails: 3
[+] Parameters: 28
[+] Sensitive Keywords Found: 5
```

Reports land in `reports/` as timestamped `.json` and `.html` files. The HTML report is a self-contained dark-mode dashboard — internal URLs, JS files, categorized JS-derived endpoints (API paths, GraphQL, WebSocket, S3 buckets), forms with CSRF/file-upload risk flags, IDOR-candidate parameter names, possible secrets (masked previews, not full values), and any accessible sensitive files.

## Project layout

```text
recon-scraper/
├── recon-scraper.py          # CLI entry point
├── crawler.py        # async crawler (scope, robots.txt, concurrency, rate limiting)
├── extractor.py       # HTML parsing: links, JS srcs, forms, emails, comments
├── analyzer.py        # orchestrates extraction + modules into one findings set
├── reporter.py         # JSON + HTML report generation
├── utils.py             # logging, URL normalization, scope checks
├── modules/
│   ├── js_parser.py      # API/GraphQL/WebSocket/S3 endpoint regexes for JS content
│   ├── secrets.py         # context-aware secret detection w/ entropy filtering
│   ├── parameters.py       # query/form param extraction + IDOR-naming heuristics
│   ├── forms.py              # form risk flags (missing CSRF, file upload, etc)
│   ├── api_finder.py          # opt-in probing of well-known sensitive paths
│   └── renderer.py             # optional Playwright rendering for SPAs
└── reports/                     # generated output
```

## Design notes / built-in guardrails

- **Explicit scope allow-list** (`utils.in_scope`) — the crawler will not wander onto third-party domains found in links; only the target domain (and subdomains, if `--include-subdomains` is passed) are followed.
- **robots.txt respected by default** — pass `--no-robots` only when your authorization explicitly covers it.
- **Rate limiting & concurrency caps** — `--delay` and `--concurrency` exist so you don't hammer a target; tune them to the program's stated limits.
- **Secret detection is context-aware, not keyword search** — matches on `key = "value"` assignment patterns plus a Shannon-entropy threshold, and only shows masked previews (`AIza…VGdc`) rather than full values, since this is meant for triage, not exfiltration.
- **`--check-files` is opt-in** — the only active probing beyond normal crawling; it's a short, fixed list of well-known paths (`.env`, `.git/HEAD`, `backup.zip`, etc.), the same class of check any standard recon tool performs.
- **IDOR/admin parameter flags are naming heuristics only** — they highlight parameter names worth manually testing, not confirmed vulnerabilities.
