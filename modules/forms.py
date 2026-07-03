"""
Lightweight risk flags on already-extracted form data (see extractor.py for
the actual HTML parsing). Heuristics only — for a human to triage, not a
vulnerability verdict.
"""


def analyze_forms(forms: list):
    flags = []
    for form in forms:
        issues = []

        if form["method"] == "GET":
            names = [i["name"].lower() for i in form["inputs"] if i.get("name")]
            if any("pass" in n for n in names):
                issues.append("password-like field submitted via GET (may leak into logs/history)")

        if not form["csrf_protected"] and form["method"] == "POST":
            issues.append("POST form with no obvious CSRF token field")

        if any(i.get("type") == "file" for i in form["inputs"]):
            issues.append("file upload field present")

        if issues:
            flags.append({
                "action": form["action"],
                "found_on": form["found_on"],
                "method": form["method"],
                "issues": issues,
            })
    return flags
