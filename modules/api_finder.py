"""
Checks a small, well-known set of paths that commonly leak information
(.env, .git/config, backup archives, API docs, etc). This is active probing
of the target's own web root — a handful of extra GET requests to paths the
target itself is serving — same class of check as any standard recon tool
(nmap http-enum, gobuster with a small wordlist, etc). Only runs when the
user opts in with --check-files, and only against in-scope hosts.
"""

import aiohttp
import asyncio

from utils import log_success, log_info

INTERESTING_PATHS = [
    ".env",
    ".git/config",
    ".git/HEAD",
    "backup.zip",
    "backup.sql",
    "config.php.bak",
    "swagger.json",
    "swagger-ui.html",
    "api-docs",
    "api/swagger.json",
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "server-status",
    ".DS_Store",
    "wp-config.php.bak",
    "web.config",
    "docker-compose.yml",
    "id_rsa",
]


async def check_interesting_files(session: aiohttp.ClientSession, base_url: str, timeout: int = 8):
    """base_url should be scheme://host with no trailing path. Returns list of hits."""
    hits = []
    base = base_url.rstrip("/")

    async def check_one(path):
        url = f"{base}/{path}"
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False, allow_redirects=False
            ) as resp:
                if resp.status == 200:
                    length = resp.headers.get("Content-Length", "?")
                    hits.append({"url": url, "status": resp.status, "content_length": length})
                    log_success(f"Interesting file accessible: {url} [{resp.status}]")
        except Exception:
            pass

    await asyncio.gather(*(check_one(p) for p in INTERESTING_PATHS))
    return hits
