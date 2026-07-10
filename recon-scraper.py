#!/usr/bin/env python3
"""
recon_scraper — authorized web recon tool.

Usage:
    python main.py -u https://example.com
    python main.py -u https://example.com --depth 2 --max-pages 200 --check-files
    python main.py -u https://example.com --include-subdomains --no-robots --delay 0.5
"""

import argparse
import asyncio
import sys
import time
from urllib.parse import urlparse

from crawler import Crawler
from extractor import extract_links
from analyzer import analyze
from reporter import write_json_report, write_html_report
from utils import get_domain, get_root_domain, log_info, log_success, log_warn, log_error, Color


BANNER = r"""
 ____                       ____
|  _ \ ___  ___ ___  _ __  / ___|  ___ _ __ __ _ _ __   ___ _ __
| |_) / _ \/ __/ _ \| '_ \ \___ \ / __| '__/ _` | '_ \ / _ \ '__|
|  _ <  __/ (_| (_) | | | | ___) | (__| | | (_| | |_) |  __/ |
|_| \_\___|\___\___/|_| |_||____/ \___|_|  \__,_| .__/ \___|_|
                                                 |_|

"""


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Recon-oriented web scraper for authorized security testing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-u", "--url", required=True, help="Target start URL, e.g. https://example.com")
    p.add_argument("--depth", type=int, default=3, help="Max crawl depth (default: 3)")
    p.add_argument("--max-pages", type=int, default=300, help="Max pages to visit (default: 300)")
    p.add_argument("--concurrency", type=int, default=10, help="Concurrent requests (default: 10)")
    p.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between requests per worker (default: 0)")
    p.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10)")
    p.add_argument("--include-subdomains", action="store_true", help="Allow crawling subdomains of the target's root domain")
    p.add_argument("--extra-domain", action="append", default=[], help="Additional allowed domain (repeatable)")
    p.add_argument("--no-robots", action="store_true", help="Do not respect robots.txt (only if your authorization permits this)")
    p.add_argument("--check-files", action="store_true", help="Actively probe a small list of common sensitive paths (.env, .git/config, etc)")
    p.add_argument("--render", action="store_true", help="Use headless browser (Playwright) to render JS-heavy pages after the initial crawl")
    p.add_argument("--screenshots", action="store_true", help="Save full-page screenshots when --render is used")
    p.add_argument("--user-agent", default="recon-scraper/1.0 (+authorized-security-testing)", help="Custom User-Agent string")
    p.add_argument("--out", default="reports", help="Output directory for reports (default: reports/)")
    p.add_argument("--json-only", action="store_true", help="Only write the JSON report, skip HTML")
    return p


def confirm_authorization(target: str) -> bool:
    print(f"\n{Color.YELLOW}This tool will actively crawl and send requests to:{Color.END} {Color.BOLD}{target}{Color.END}")


async def run(args):
    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        log_error("URL must start with http:// or https://")
        sys.exit(1)

    root_domain = get_root_domain(args.url)
    target_domain = get_domain(args.url)

    allowed_domains = {target_domain}
    if args.include_subdomains:
        allowed_domains.add(root_domain)
    allowed_domains.update(args.extra_domain)

    log_info(f"Target: {args.url}")
    log_info(f"Allowed domain scope: {', '.join(sorted(allowed_domains))}")
    log_info(f"Max depth: {args.depth} | Max pages: {args.max_pages} | Concurrency: {args.concurrency}")
    if args.no_robots:
        log_warn("robots.txt checking is DISABLED for this run")

    start = time.time()

    crawler = Crawler(
        start_url=args.url,
        allowed_domains=allowed_domains,
        max_depth=args.depth,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        delay=args.delay,
        timeout=args.timeout,
        respect_robots=not args.no_robots,
        user_agent=args.user_agent,
    )

    log_info("Starting crawl...")
    crawl_result = await crawler.crawl(extract_links)
    log_success(f"Crawl complete: {len(crawl_result.pages)} pages fetched, {len(crawl_result.errors)} errors")

    if args.render:
        from modules.renderer import render_pages
        log_info("Rendering pages with headless browser for JS-heavy content...")
        screenshot_dir = f"{args.out}/screenshots" if args.screenshots else None
        rendered = render_pages(
            [p.url for p in crawl_result.pages],
            screenshot_dir=screenshot_dir,
            user_agent=args.user_agent,
        )
        # Replace/augment page HTML with rendered DOM where available
        for page in crawl_result.pages:
            if page.url in rendered:
                page.html = rendered[page.url]

    log_info("Analyzing content (JS endpoints, secrets, forms, params)...")
    analysis = await analyze(
        crawl_result,
        args.url,
        check_files=args.check_files,
        timeout=args.timeout,
        concurrency=args.concurrency,
        user_agent=args.user_agent,
    )

    elapsed = time.time() - start
    data = analysis.to_dict()

    print(f"\n{Color.BOLD}=== Recon Summary ({elapsed:.1f}s) ==={Color.END}")
    print(f"[+] Internal URLs: {len(data['internal_urls'])}")
    print(f"[+] JavaScript Files: {len(data['js_files'])}")
    api_paths = data['js_endpoint_findings'].get('api_paths', [])
    full_urls = data['js_endpoint_findings'].get('full_urls', [])
    print(f"[+] API Endpoints (relative): {len(api_paths)}")
    print(f"[+] Full URLs found in JS: {len(full_urls)}")
    print(f"[+] Forms: {len(data['forms'])}  (risky: {len(data['form_risk_flags'])})")
    print(f"[+] Emails: {len(data['emails'])}")
    print(f"[+] Parameters: {len(data['params'])}  (IDOR-candidates: {len(data['idor_candidates'])})")
    print(f"[+] Possible Secrets: {len(data['secrets'])}")
    if args.check_files:
        print(f"[+] Interesting Files Accessible: {len(data['interesting_files'])}")
    print()

    json_path = write_json_report(analysis, args.url, out_dir=args.out)
    log_success(f"JSON report written: {json_path}")

    if not args.json_only:
        html_path = write_html_report(analysis, args.url, out_dir=args.out)
        log_success(f"HTML report written: {html_path}")


def main():
    print(f"{Color.CYAN}{BANNER}{Color.END}")
    args = build_arg_parser().parse_args()
    confirm_authorization(args.url)

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        log_warn("Interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
