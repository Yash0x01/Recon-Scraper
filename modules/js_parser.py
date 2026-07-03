"""
Parses JavaScript content (external files + inline blocks) for interesting
endpoints, cloud storage references, and misc URLs.
"""

import re

FULL_URL_REGEX = re.compile(r"https?://[^\s'\"<>)]+")
RELATIVE_API_REGEX = re.compile(r"""["'](/[a-zA-Z0-9_\-/]*(?:api|v[0-9]+|graphql|rest)[a-zA-Z0-9_\-/]*)["']""", re.I)
GRAPHQL_REGEX = re.compile(r"""["'](/[^"']*graphql[^"']*)["']""", re.I)
WEBSOCKET_REGEX = re.compile(r"""wss?://[^\s'"<>)]+""")
S3_BUCKET_REGEX = re.compile(r"[a-zA-Z0-9\-_.]+\.s3(?:[.\-][a-zA-Z0-9\-]+)?\.amazonaws\.com")
FIREBASE_REGEX = re.compile(r"[a-zA-Z0-9\-_]+\.firebaseio\.com")
SWAGGER_REGEX = re.compile(r"""["']([^"']*(?:swagger|openapi)[^"']*\.json)["']""", re.I)


def find_endpoints(js_content: str):
    """Return a dict of categorized findings from a blob of JS source."""
    findings = {
        "full_urls": set(),
        "api_paths": set(),
        "graphql_endpoints": set(),
        "websocket_endpoints": set(),
        "s3_buckets": set(),
        "firebase_urls": set(),
        "swagger_docs": set(),
    }

    findings["full_urls"].update(FULL_URL_REGEX.findall(js_content))
    findings["api_paths"].update(m for m in RELATIVE_API_REGEX.findall(js_content))
    findings["graphql_endpoints"].update(GRAPHQL_REGEX.findall(js_content))
    findings["websocket_endpoints"].update(WEBSOCKET_REGEX.findall(js_content))
    findings["s3_buckets"].update(S3_BUCKET_REGEX.findall(js_content))
    findings["firebase_urls"].update(FIREBASE_REGEX.findall(js_content))
    findings["swagger_docs"].update(SWAGGER_REGEX.findall(js_content))

    return findings


def merge_findings(target: dict, source: dict):
    for key, values in source.items():
        target.setdefault(key, set())
        target[key].update(values)
    return target
