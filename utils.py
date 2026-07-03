"""
Shared utilities: colored logging, URL helpers, scope control.
"""

import re
from urllib.parse import urlparse, urljoin, urldefrag


class Color:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


def log_info(msg: str):
    print(f"{Color.CYAN}[*]{Color.END} {msg}")


def log_success(msg: str):
    print(f"{Color.GREEN}[+]{Color.END} {msg}")


def log_warn(msg: str):
    print(f"{Color.YELLOW}[!]{Color.END} {msg}")


def log_error(msg: str):
    print(f"{Color.RED}[-]{Color.END} {msg}")


def normalize_url(base: str, link: str) -> str:
    """Resolve a relative link against a base URL and strip fragments."""
    try:
        absolute = urljoin(base, link)
        absolute, _ = urldefrag(absolute)
        return absolute.strip()
    except Exception:
        return ""


def get_domain(url: str) -> str:
    return urlparse(url).netloc.lower()


def get_root_domain(url: str) -> str:
    """Best-effort root domain (last two labels), e.g. sub.example.com -> example.com."""
    netloc = get_domain(url)
    parts = netloc.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return netloc


def in_scope(url: str, allowed_domains: set, include_subdomains: bool = True) -> bool:
    """
    Scope check against an explicit allow-list. This exists specifically so the
    crawler cannot wander off the authorized target(s) onto third-party domains.
    """
    domain = get_domain(url)
    if not domain:
        return False
    if domain in allowed_domains:
        return True
    if include_subdomains:
        for allowed in allowed_domains:
            if domain.endswith("." + allowed):
                return True
    return False


def is_static_asset(url: str) -> bool:
    """Skip binary/media assets that aren't useful for recon crawling."""
    skip_ext = (
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".css",
        ".mp4", ".mp3", ".avi", ".mov", ".pdf",
        ".zip", ".tar", ".gz", ".rar",
    )
    path = urlparse(url).path.lower()
    return path.endswith(skip_ext)


def clean_param_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-\[\]]", "", name)
