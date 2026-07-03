"""
Extracts structural data out of raw HTML: links, script sources, forms,
emails, and HTML comments. Kept separate from analysis (secrets/params/api)
which lives in modules/.
"""

import re
from bs4 import BeautifulSoup
import warnings

from utils import normalize_url

EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
COMMENT_REGEX = re.compile(r"<!--(.*?)-->", re.DOTALL)

warnings.filterwarnings("ignore", category=DeprecationWarning)

def extract_links(base_url: str, html: str):
    """Return absolute URLs found in <a href>, <link href>, and <area href>."""
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag, attr in (("a", "href"), ("link", "href"), ("area", "href")):
        for el in soup.find_all(tag, **{attr: True}):
            url = normalize_url(base_url, el[attr])
            if url.startswith("http"):
                links.add(url)
    return links


def extract_js_files(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")
    js_files = set()
    for script in soup.find_all("script", src=True):
        url = normalize_url(base_url, script["src"])
        if url:
            js_files.add(url)
    return js_files


def extract_inline_scripts(html: str):
    """Return contents of inline <script> blocks (no src) for endpoint/secret scanning."""
    soup = BeautifulSoup(html, "html.parser")
    blocks = []
    for script in soup.find_all("script", src=False):
        if script.string:
            blocks.append(script.string)
    return blocks


def extract_forms(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = normalize_url(base_url, form.get("action", "")) or base_url
        method = form.get("method", "GET").upper()
        inputs = []
        csrf_token_present = False
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            itype = inp.get("type", "text") if inp.name == "input" else inp.name
            if name and re.search(r"csrf|token|_token|authenticity", name, re.I):
                csrf_token_present = True
            inputs.append({"name": name, "type": itype})
        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
            "csrf_protected": csrf_token_present,
            "found_on": base_url,
        })
    return forms


def extract_emails(html: str):
    return set(EMAIL_REGEX.findall(html))


def extract_comments(html: str):
    """Return non-trivial HTML comments (skip short/whitespace-only ones)."""
    comments = []
    for c in COMMENT_REGEX.findall(html):
        c = c.strip()
        if len(c) > 5:
            comments.append(c)
    return comments
