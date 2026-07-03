"""
Turns an Analysis object into JSON and a self-contained HTML dashboard.
"""

import json
import os
from datetime import datetime, timezone


def write_json_report(analysis, target: str, out_dir: str = "reports") -> str:
    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    path = os.path.join(out_dir, f"{safe_target}_{timestamp}.json")

    payload = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": analysis.to_dict(),
    }

    with open(path, "w") as f:
        json.dump(payload, f, indent=2)

    return path


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _section(title: str, count: int, body_html: str) -> str:
    return f"""
    <section class="card">
      <h2>{_esc(title)} <span class="count">{count}</span></h2>
      <div class="card-body">{body_html}</div>
    </section>
    """


def _list_html(items, empty_msg="None found"):
    if not items:
        return f"<p class='empty'>{_esc(empty_msg)}</p>"
    rows = "".join(f"<li>{_esc(i)}</li>" for i in items)
    return f"<ul>{rows}</ul>"


def write_html_report(analysis, target: str, out_dir: str = "reports") -> str:
    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://", "").replace("http://", "").replace("/", "_")
    path = os.path.join(out_dir, f"{safe_target}_{timestamp}.html")

    data = analysis.to_dict()

    secrets_rows = "".join(
        f"<tr><td>{_esc(s['type'])}</td><td>{_esc(s['confidence'])}</td>"
        f"<td class='mono'>{_esc(s['value_preview'])}</td><td class='mono small'>{_esc(s['source'])}</td></tr>"
        for s in data["secrets"]
    ) or "<tr><td colspan='4' class='empty'>None found</td></tr>"

    forms_rows = "".join(
        f"<tr><td>{_esc(f['method'])}</td><td class='mono'>{_esc(f['action'])}</td>"
        f"<td>{len(f['inputs'])}</td><td>{'yes' if f['csrf_protected'] else 'NO'}</td></tr>"
        for f in data["forms"]
    ) or "<tr><td colspan='4' class='empty'>None found</td></tr>"

    form_flags_rows = "".join(
        f"<tr><td class='mono'>{_esc(f['action'])}</td><td>{_esc(', '.join(f['issues']))}</td></tr>"
        for f in data["form_risk_flags"]
    ) or "<tr><td colspan='2' class='empty'>None found</td></tr>"

    interesting_files_rows = "".join(
        f"<tr><td class='mono'>{_esc(h['url'])}</td><td>{_esc(h['status'])}</td><td>{_esc(h['content_length'])}</td></tr>"
        for h in data["interesting_files"]
    ) or "<tr><td colspan='3' class='empty'>None checked / none found</td></tr>"

    js_endpoint_sections = ""
    for category, values in data["js_endpoint_findings"].items():
        if values:
            js_endpoint_sections += _section(category.replace("_", " ").title(), len(values), _list_html(values))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Recon Report — {_esc(target)}</title>
<style>
  :root {{
    --bg: #0b0d12; --card: #12151c; --border: #232734; --text: #e6e8ee;
    --muted: #8a92a6; --accent: #5eead4; --warn: #f6c445; --danger: #f66;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text); font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    margin: 0; padding: 2rem;
  }}
  header {{ margin-bottom: 2rem; }}
  header h1 {{ font-size: 1.4rem; margin: 0 0 0.25rem; }}
  header .meta {{ color: var(--muted); font-size: 0.85rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 1rem; }}
  .card {{
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 1rem 1.25rem; overflow: hidden;
  }}
  .card h2 {{
    font-size: 0.95rem; margin: 0 0 0.75rem; display: flex; justify-content: space-between; align-items: center;
    color: var(--accent); text-transform: uppercase; letter-spacing: 0.03em;
  }}
  .card .count {{
    background: var(--border); color: var(--text); border-radius: 999px; padding: 0.1rem 0.6rem; font-size: 0.75rem;
  }}
  .card-body {{ max-height: 260px; overflow-y: auto; font-size: 0.85rem; }}
  ul {{ margin: 0; padding-left: 1.1rem; }}
  li {{ margin-bottom: 0.3rem; word-break: break-all; color: var(--text); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
  td, th {{ padding: 0.35rem 0.4rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
  .mono {{ font-family: "SF Mono", Menlo, monospace; word-break: break-all; }}
  .small {{ font-size: 0.72rem; color: var(--muted); }}
  .empty {{ color: var(--muted); font-style: italic; }}
  .summary-bar {{
    display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem;
  }}
  .stat {{
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 0.75rem 1.25rem; min-width: 120px;
  }}
  .stat .n {{ font-size: 1.6rem; font-weight: 700; color: var(--accent); }}
  .stat .l {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; }}
</style>
</head>
<body>
<header>
  <h1>Recon Report — {_esc(target)}</h1>
  <div class="meta">Generated {_esc(datetime.now(timezone.utc).isoformat())} UTC</div>
</header>

<div class="summary-bar">
  <div class="stat"><div class="n">{len(data['internal_urls'])}</div><div class="l">URLs</div></div>
  <div class="stat"><div class="n">{len(data['js_files'])}</div><div class="l">JS Files</div></div>
  <div class="stat"><div class="n">{len(data['forms'])}</div><div class="l">Forms</div></div>
  <div class="stat"><div class="n">{len(data['emails'])}</div><div class="l">Emails</div></div>
  <div class="stat"><div class="n">{len(data['params'])}</div><div class="l">Parameters</div></div>
  <div class="stat"><div class="n">{len(data['secrets'])}</div><div class="l">Secret Hits</div></div>
</div>

<div class="grid">
  {_section("Internal URLs", len(data['internal_urls']), _list_html(data['internal_urls']))}
  {_section("JavaScript Files", len(data['js_files']), _list_html(data['js_files']))}
  {_section("Parameters", len(data['params']), _list_html(data['params']))}
  {_section("IDOR-Candidate Params", len(data['idor_candidates']), _list_html(data['idor_candidates'], "None matched naming heuristics"))}
  {_section("Admin-Related Params", len(data['admin_param_candidates']), _list_html(data['admin_param_candidates']))}
  {_section("Emails", len(data['emails']), _list_html(data['emails']))}
  {js_endpoint_sections}
  <section class="card">
    <h2>Forms <span class="count">{len(data['forms'])}</span></h2>
    <div class="card-body"><table><tr><th>Method</th><th>Action</th><th>#Inputs</th><th>CSRF?</th></tr>{forms_rows}</table></div>
  </section>
  <section class="card">
    <h2>Form Risk Flags <span class="count">{len(data['form_risk_flags'])}</span></h2>
    <div class="card-body"><table><tr><th>Action</th><th>Issues</th></tr>{form_flags_rows}</table></div>
  </section>
  <section class="card">
    <h2>Possible Secrets <span class="count">{len(data['secrets'])}</span></h2>
    <div class="card-body"><table><tr><th>Type</th><th>Confidence</th><th>Preview</th><th>Source</th></tr>{secrets_rows}</table></div>
  </section>
  <section class="card">
    <h2>Interesting Files <span class="count">{len(data['interesting_files'])}</span></h2>
    <div class="card-body"><table><tr><th>URL</th><th>Status</th><th>Length</th></tr>{interesting_files_rows}</table></div>
  </section>
  {_section("HTML Comments", len(data['comments']), _list_html([f"{c['source']}: {c['comment']}" for c in data['comments']]))}
</div>

</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)

    return path
