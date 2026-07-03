"""
Optional dynamic rendering for JavaScript-heavy sites (React/Angular/Vue SPAs)
that don't expose meaningful content in the raw HTML response. Only used when
--render is passed, since it's much slower than the plain aiohttp crawler.
"""

import os

from utils import log_info, log_warn, log_success


def render_pages(urls, screenshot_dir: str = None, timeout_ms: int = 15000, user_agent: str = "recon-scraper/1.0"):
    """
    Synchronously render each URL with a headless browser and return
    {url: rendered_html}. Screenshots are saved if screenshot_dir is given.
    Requires: pip install playwright && playwright install chromium
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log_warn("Playwright not installed — skipping dynamic rendering. "
                  "Install with: pip install playwright && playwright install chromium")
        return {}

    rendered = {}

    if screenshot_dir:
        os.makedirs(screenshot_dir, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(user_agent=user_agent)
        page = context.new_page()

        for url in urls:
            try:
                page.goto(url, timeout=timeout_ms, wait_until="networkidle")
                rendered[url] = page.content()
                log_success(f"Rendered: {url}")

                if screenshot_dir:
                    safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_")[:150]
                    shot_path = os.path.join(screenshot_dir, f"{safe_name}.png")
                    page.screenshot(path=shot_path, full_page=True)
            except Exception as e:
                log_warn(f"Failed to render {url}: {e}")

        browser.close()

    return rendered
