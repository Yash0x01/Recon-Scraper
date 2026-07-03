"""
Context-aware secret detection. Bare keyword matching (e.g. searching for the
word "password" anywhere in a page) produces huge false-positive rates, so
this module instead looks for `key = "value"` style assignments and applies
a Shannon-entropy threshold to the captured value before flagging it.
"""

import math
import re

# Each pattern captures the *value* in group(1).
PATTERNS = {
    "generic_api_key": re.compile(
        r"""(?i)api[_-]?key["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']"""
    ),
    "generic_secret": re.compile(
        r"""(?i)\bsecret["']?\s*[:=]\s*["']([a-zA-Z0-9_\-]{12,})["']"""
    ),
    "password_assignment": re.compile(
        r"""(?i)password["']?\s*[:=]\s*["']([^"'\s]{6,})["']"""
    ),
    "bearer_token": re.compile(
        r"""(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})"""
    ),
    "aws_access_key_id": re.compile(
        r"""\b(AKIA[0-9A-Z]{16})\b"""
    ),
    "aws_secret_key": re.compile(
        r"""(?i)aws_secret_access_key["']?\s*[:=]\s*["']([a-zA-Z0-9/+=]{40})["']"""
    ),
    "private_key_block": re.compile(
        r"""(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"""
    ),
    "slack_token": re.compile(
        r"""(xox[baprs]-[a-zA-Z0-9\-]{10,})"""
    ),
    "google_api_key": re.compile(
        r"""(AIza[0-9A-Za-z\-_]{35})"""
    ),
    "jwt": re.compile(
        r"""(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)"""
    ),
}

# Placeholder values that trip the regexes but aren't real secrets.
PLACEHOLDER_VALUES = {
    "your_api_key", "your-api-key", "changeme", "xxxxxxxx", "example",
    "placeholder", "insert_key_here", "test", "demo", "null", "undefined",
    "your_secret_here", "0000000000000000",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def find_secrets(content: str, source_url: str = ""):
    """
    Scan `content` and return a list of findings:
    [{"type": ..., "value_preview": ..., "source": ..., "confidence": "high"|"medium"}]
    Values are truncated/masked in the preview — this tool flags likely
    secrets for manual triage, it does not exfiltrate full credential values.
    """
    findings = []

    for secret_type, pattern in PATTERNS.items():
        for match in pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            if value.lower() in PLACEHOLDER_VALUES:
                continue

            confidence = "medium"
            if secret_type in ("aws_access_key_id", "aws_secret_key", "slack_token",
                                "google_api_key", "private_key_block", "jwt"):
                confidence = "high"
            elif len(value) >= 20 and shannon_entropy(value) >= 3.5:
                confidence = "high"
            elif shannon_entropy(value) < 2.5:
                # Looks like a word/sentence, not a random token — skip
                continue

            masked = value[:4] + "…" + value[-4:] if len(value) > 10 else "…"
            findings.append({
                "type": secret_type,
                "value_preview": masked,
                "source": source_url,
                "confidence": confidence,
            })

    return findings
