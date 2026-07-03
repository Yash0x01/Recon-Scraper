"""
Extracts query/body parameter names from URLs and forms, and flags
parameter names that are commonly associated with IDOR / access-control
issues (purely a naming heuristic — always needs manual verification).
"""

import re
from urllib.parse import urlparse, parse_qs

PARAM_REGEX = re.compile(r"[?&]([a-zA-Z0-9_\[\]\.]+)=")

IDOR_HINTS = re.compile(
    r"^(id|user_?id|account_?id|order_?id|invoice_?id|doc_?id|file_?id|"
    r"uid|uuid|pid|cust(omer)?_?id|profile_?id|record_?id)$",
    re.I,
)

ADMIN_HINTS = re.compile(r"(admin|debug|internal|staff|superuser)", re.I)


def extract_params_from_url(url: str):
    params = set()
    query = urlparse(url).query
    if query:
        for name in parse_qs(query).keys():
            params.add(name)
    # also catch malformed / non-standard param-looking strings
    params.update(PARAM_REGEX.findall(url))
    return params


def extract_params_from_forms(forms: list):
    params = set()
    for form in forms:
        for inp in form.get("inputs", []):
            if inp.get("name"):
                params.add(inp["name"])
    return params


def flag_interesting_params(all_params: set):
    """Return (idor_candidates, admin_candidates) subsets of all_params."""
    idor = {p for p in all_params if IDOR_HINTS.match(p)}
    admin = {p for p in all_params if ADMIN_HINTS.search(p)}
    return idor, admin
