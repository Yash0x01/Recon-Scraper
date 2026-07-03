"""
Async crawler. Respects scope, robots.txt (optional), rate limiting and
concurrency limits. Produces raw (url, html, status, headers) tuples that
downstream extractors consume.
"""

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse
from urllib import robotparser

import aiohttp

from utils import normalize_url, in_scope, is_static_asset, log_info, log_warn, log_success


@dataclass
class Page:
    url: str
    status: int
    html: str
    headers: dict


@dataclass
class CrawlResult:
    pages: list = field(default_factory=list)     # list[Page]
    visited: set = field(default_factory=set)
    errors: dict = field(default_factory=dict)     # url -> error string


class Crawler:
    def __init__(
        self,
        start_url: str,
        allowed_domains: set,
        max_depth: int = 3,
        max_pages: int = 500,
        concurrency: int = 10,
        delay: float = 0.0,
        timeout: int = 10,
        respect_robots: bool = True,
        user_agent: str = "recon-scraper/1.0 (+authorized-security-testing)",
        use_playwright: bool = False,
    ):
        self.start_url = start_url
        self.allowed_domains = allowed_domains
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.delay = delay
        self.timeout = timeout
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self.use_playwright = use_playwright

        self.result = CrawlResult()
        self._queue = asyncio.Queue()
        self._sem = asyncio.Semaphore(concurrency)
        self._robots_cache = {}

    # ---------- robots.txt ----------

    def _robots_allowed(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._robots_cache:
            rp = robotparser.RobotFileParser()
            try:
                rp.set_url(base + "/robots.txt")
                rp.read()
            except Exception:
                rp = None
            self._robots_cache[base] = rp
        rp = self._robots_cache[base]
        if rp is None:
            return True
        try:
            return rp.can_fetch(self.user_agent, url)
        except Exception:
            return True

    # ---------- fetching ----------

    async def _fetch(self, session: aiohttp.ClientSession, url: str):
        async with self._sem:
            if self.delay:
                await asyncio.sleep(self.delay)
            try:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    content_type = resp.headers.get("Content-Type", "")
                    if "text" in content_type or "javascript" in content_type or "json" in content_type or content_type == "":
                        text = await resp.text(errors="ignore")
                    else:
                        text = ""
                    return Page(url=str(resp.url), status=resp.status, html=text, headers=dict(resp.headers))
            except Exception as e:
                self.result.errors[url] = str(e)
                return None

    async def _worker(self, session, extract_links_fn):
        while True:
            try:
                url, depth = await asyncio.wait_for(self._queue.get(), timeout=3)
            except asyncio.TimeoutError:
                return

            if url in self.result.visited:
                self._queue.task_done()
                continue
            if len(self.result.visited) >= self.max_pages:
                self._queue.task_done()
                continue

            self.result.visited.add(url)

            if not self._robots_allowed(url):
                log_warn(f"robots.txt disallows: {url}")
                self._queue.task_done()
                continue

            page = await self._fetch(session, url)
            if page is not None:
                self.result.pages.append(page)
                log_success(f"[{page.status}] {url}") if page.status == 200 else log_warn(f"[{page.status}] {url}")

                if depth < self.max_depth and page.html:
                    for link in extract_links_fn(page.url, page.html):
                        if is_static_asset(link):
                            continue
                        if in_scope(link, self.allowed_domains) and link not in self.result.visited:
                            await self._queue.put((link, depth + 1))

            self._queue.task_done()

    async def crawl(self, extract_links_fn):
        """
        extract_links_fn(base_url, html) -> iterable[str] of absolute URLs.
        Injected from extractor.py to avoid circular imports.
        """
        await self._queue.put((self.start_url, 0))

        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(
            headers={"User-Agent": self.user_agent}, connector=connector
        ) as session:
            workers = [
                asyncio.create_task(self._worker(session, extract_links_fn))
                for _ in range(self.concurrency)
            ]
            # Keep spawning until queue drains and all workers idle out
            await asyncio.gather(*workers)

        return self.result
