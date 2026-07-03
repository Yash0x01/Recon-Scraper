"""
Takes the raw CrawlResult (list of Page objects) and runs all extractors/
modules over it, producing one consolidated findings dict that reporter.py
turns into JSON/HTML.
"""

import asyncio
from urllib.parse import urlparse

import aiohttp

from extractor import (
    extract_links, extract_js_files, extract_inline_scripts,
    extract_forms, extract_emails, extract_comments,
)
from modules.js_parser import find_endpoints, merge_findings
from modules.secrets import find_secrets
from modules.parameters import extract_params_from_url, extract_params_from_forms, flag_interesting_params
from modules.forms import analyze_forms
from modules.api_finder import check_interesting_files
from utils import log_info, log_success


async def fetch_js_files(js_urls: set, timeout: int = 10, concurrency: int = 10, user_agent: str = "recon-scraper/1.0"):
    """Download JS files so their contents can be scanned for endpoints/secrets."""
    results = {}
    sem = asyncio.Semaphore(concurrency)

    async def fetch_one(session, url):
        async with sem:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as resp:
                    if resp.status == 200:
                        results[url] = await resp.text(errors="ignore")
            except Exception:
                pass

    async with aiohttp.ClientSession(headers={"User-Agent": user_agent}) as session:
        await asyncio.gather(*(fetch_one(session, u) for u in js_urls))
    return results


class Analysis:
    def __init__(self):
        self.internal_urls = set()
        self.js_files = set()
        self.js_endpoint_findings = {}
        self.forms = []
        self.form_risk_flags = []
        self.emails = set()
        self.comments = []          # list of (source_url, comment_text)
        self.secrets = []
        self.params = set()
        self.idor_candidates = set()
        self.admin_param_candidates = set()
        self.interesting_files = []
        self.errors = {}

    def to_dict(self):
        return {
            "internal_urls": sorted(self.internal_urls),
            "js_files": sorted(self.js_files),
            "js_endpoint_findings": {k: sorted(v) for k, v in self.js_endpoint_findings.items()},
            "forms": self.forms,
            "form_risk_flags": self.form_risk_flags,
            "emails": sorted(self.emails),
            "comments": self.comments,
            "secrets": self.secrets,
            "params": sorted(self.params),
            "idor_candidates": sorted(self.idor_candidates),
            "admin_param_candidates": sorted(self.admin_param_candidates),
            "interesting_files": self.interesting_files,
            "errors": self.errors,
        }


async def analyze(crawl_result, start_url: str, check_files: bool = False,
                   timeout: int = 10, concurrency: int = 10,
                   user_agent: str = "recon-scraper/1.0"):
    analysis = Analysis()
    analysis.errors = crawl_result.errors

    all_forms_raw = []

    for page in crawl_result.pages:
        analysis.internal_urls.add(page.url)

        if not page.html:
            continue

        analysis.js_files.update(extract_js_files(page.url, page.html))
        analysis.emails.update(extract_emails(page.html))

        for c in extract_comments(page.html):
            analysis.comments.append({"source": page.url, "comment": c[:300]})

        page_forms = extract_forms(page.url, page.html)
        all_forms_raw.extend(page_forms)
        analysis.params.update(extract_params_from_url(page.url))

        # secrets in the raw HTML + inline scripts
        analysis.secrets.extend(find_secrets(page.html, source_url=page.url))
        for block in extract_inline_scripts(page.html):
            analysis.secrets.extend(find_secrets(block, source_url=page.url + " (inline script)"))
            analysis.js_endpoint_findings = merge_findings(analysis.js_endpoint_findings, find_endpoints(block))

    analysis.forms = all_forms_raw
    analysis.form_risk_flags = analyze_forms(all_forms_raw)
    analysis.params.update(extract_params_from_forms(all_forms_raw))
    analysis.idor_candidates, analysis.admin_param_candidates = flag_interesting_params(analysis.params)

    # Download and scan external JS files
    if analysis.js_files:
        log_info(f"Downloading {len(analysis.js_files)} JavaScript files for endpoint/secret analysis...")
        js_contents = await fetch_js_files(analysis.js_files, timeout=timeout, concurrency=concurrency, user_agent=user_agent)
        for url, content in js_contents.items():
            analysis.js_endpoint_findings = merge_findings(analysis.js_endpoint_findings, find_endpoints(content))
            analysis.secrets.extend(find_secrets(content, source_url=url))

    # Optional active probing for well-known sensitive paths
    if check_files:
        parsed = urlparse(start_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        log_info(f"Checking common sensitive paths on {base} ...")
        async with aiohttp.ClientSession(headers={"User-Agent": user_agent}) as session:
            analysis.interesting_files = await check_interesting_files(session, base, timeout=timeout)

    return analysis
