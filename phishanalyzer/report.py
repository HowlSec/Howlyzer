"""Console, JSON, and self-contained HTML report rendering.

The HTML report escapes every piece of attacker-controlled text (subject,
sender name, finding evidence, etc.) before embedding it, and defangs every
URL/domain - the report itself must be safe to open in a browser and safe
to paste into chat/ticketing tools without anything becoming clickable.

Findings are split into two tiers everywhere (console, HTML): "Key Evidence"
(CRITICAL/HIGH - the specific findings that actually drive the verdict, e.g.
the exact phishing link or the fake sending domain) shown prominently, and
"Additional Signals" (MEDIUM/LOW/INFO - supporting context) shown compactly.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .iocs import defang
from .models import Category, Finding, Report, Severity

_VERDICT_COLOR = {
    "Likely Legitimate": "green",
    "Spam / Unwanted": "yellow",
    "Suspicious": "dark_orange",
    "Phishing": "red",
    "Malicious - High Confidence": "bold red",
}

_VERDICT_HEX = {
    "Likely Legitimate": "#2ea043",
    "Spam / Unwanted": "#9e6a03",
    "Suspicious": "#d9730d",
    "Phishing": "#da3633",
    "Malicious - High Confidence": "#f85149",
}

_SEVERITY_COLOR = {
    "info": "grey62",
    "low": "cyan",
    "medium": "yellow",
    "high": "orange3",
    "critical": "bold red",
}

_SEVERITY_HEX = {
    "critical": "#ff6b6b",
    "high": "#ff9f43",
    "medium": "#e3b341",
    "low": "#4dabf7",
    "info": "#8b949e",
}

_KEY_EVIDENCE_SEVERITIES = (Severity.CRITICAL, Severity.HIGH)


def _split_findings(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    key = sorted(
        (f for f in findings if f.severity in _KEY_EVIDENCE_SEVERITIES),
        key=lambda f: f.severity.value,
        reverse=True,
    )
    supporting = sorted(
        (f for f in findings if f.severity not in _KEY_EVIDENCE_SEVERITIES),
        key=lambda f: f.severity.value,
        reverse=True,
    )
    return key, supporting


def _suspicious_links(findings: list[Finding]) -> list[Finding]:
    return [
        f for f in findings
        if f.category == Category.URL and f.severity in _KEY_EVIDENCE_SEVERITIES and f.evidence
    ]


def _message_details(parsed) -> list[tuple[str, str]]:
    rows = [
        ("Subject", parsed.subject or "(none)"),
        ("From", f"{parsed.from_display} <{parsed.from_addr}>" if parsed.from_display else parsed.from_addr),
    ]
    if parsed.reply_to_addr and parsed.reply_to_addr != parsed.from_addr:
        rows.append(("Reply-To", parsed.reply_to_addr))
    if parsed.date:
        rows.append(("Date", parsed.date))
    rows.append(("Links found", str(len(parsed.urls))))
    rows.append(("Attachments", str(len(parsed.attachments))))
    return rows


# --------------------------------------------------------------------- console


def render_console(report: Report) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        _render_console_plain(report)
        return

    console = Console()
    verdict = report.verdict
    parsed = report.parsed
    color = _VERDICT_COLOR.get(verdict.label, "white")
    key_evidence, supporting = _split_findings(report.findings)

    console.print(
        Panel(
            f"[{color}]{verdict.label}[/{color}]\n"
            f"score={verdict.score}  phishing_score={verdict.phishing_score}  confidence={verdict.confidence}",
            title=parsed.source_path,
            expand=False,
        )
    )

    details = Table(show_header=False, box=None, padding=(0, 1))
    details.add_column(style="bold")
    details.add_column()
    for label, value in _message_details(parsed):
        details.add_row(label, value)
    console.print(details)

    links = _suspicious_links(report.findings)
    if links:
        console.print("\n[bold red]Suspicious / malicious link(s):[/bold red]")
        for f in links:
            console.print(f"  [bold]->[/bold] {f.evidence}  [dim]({f.title})[/dim]")

    if key_evidence:
        console.print("\n[bold]Key Evidence[/bold] (drives the verdict):")
        for f in key_evidence:
            sev_color = _SEVERITY_COLOR.get(f.severity.value, "white")
            console.print(f"\n  [{sev_color}]* {f.severity.value.upper()}[/{sev_color}]  [bold]{f.title}[/bold]")
            console.print(f"    {f.detail}")
            if f.evidence:
                console.print(f"    [bold yellow]evidence:[/bold yellow] {f.evidence}")
            if f.mitre:
                console.print(f"    [dim]MITRE ATT&CK: {f.mitre}[/dim]")

    if supporting:
        console.print("\n[bold]Additional Signals[/bold] (lower confidence / supporting context):")
        table = Table(show_lines=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Finding")
        table.add_column("Evidence", overflow="fold")
        for f in supporting:
            sev_color = _SEVERITY_COLOR.get(f.severity.value, "white")
            table.add_row(
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f"{f.title}\n[dim]{f.detail}[/dim]",
                f.evidence,
            )
        console.print(table)

    if not report.findings:
        console.print("\n[green]No indicators triggered.[/green]")

    console.print(f"\n[bold]Summary:[/bold]\n{report.ai_summary or verdict.summary}")
    if report.ai_summary:
        console.print("[dim](AI-generated summary via Claude)[/dim]")


def _render_console_plain(report: Report) -> None:
    verdict = report.verdict
    parsed = report.parsed
    key_evidence, supporting = _split_findings(report.findings)

    print(f"=== {parsed.source_path} ===")
    print(f"Verdict: {verdict.label}  (score={verdict.score}, phishing_score={verdict.phishing_score}, "
          f"confidence={verdict.confidence})")
    print()
    for label, value in _message_details(parsed):
        print(f"{label}: {value}")

    links = _suspicious_links(report.findings)
    if links:
        print("\nSuspicious / malicious link(s):")
        for f in links:
            print(f"  -> {f.evidence}  ({f.title})")

    if key_evidence:
        print("\nKey Evidence (drives the verdict):")
        for f in key_evidence:
            print(f"\n  [{f.severity.value.upper()}] {f.title}")
            print(f"    {f.detail}")
            if f.evidence:
                print(f"    evidence: {f.evidence}")
            if f.mitre:
                print(f"    MITRE ATT&CK: {f.mitre}")

    if supporting:
        print("\nAdditional Signals:")
        for f in supporting:
            print(f"  [{f.severity.value.upper()}] {f.category.value}: {f.title}")
            print(f"      {f.detail}")
            if f.evidence:
                print(f"      evidence: {f.evidence}")

    if not report.findings:
        print("\nNo indicators triggered.")

    print("\nSummary:")
    print(report.ai_summary or verdict.summary)


# ------------------------------------------------------------------------ json


def to_json(report: Report) -> str:
    data = {
        "source_path": report.parsed.source_path,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "subject": report.parsed.subject,
        "from_display": report.parsed.from_display,
        "from_addr": report.parsed.from_addr,
        "verdict": report.verdict.to_dict(),
        "findings": [f.to_dict() for f in report.findings],
        "iocs": report.iocs,
        "ai_summary": report.ai_summary,
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------------ html


def _esc(value: str) -> str:
    import html as _html

    return _html.escape(str(value), quote=True)


def _evidence_chip(evidence: str) -> str:
    if not evidence:
        return ""
    return f"<div class='chip'>{_esc(defang(evidence))}</div>"


def _key_evidence_card(f: Finding) -> str:
    mitre_badge = f"<span class='mitre'>{_esc(f.mitre)}</span>" if f.mitre else ""
    return f"""
    <div class="card sev-{_esc(f.severity.value)}">
      <div class="card-head">
        <span class="sev-badge sev-{_esc(f.severity.value)}">{_esc(f.severity.value.upper())}</span>
        <span class="cat-badge">{_esc(f.category.value)}</span>
        {mitre_badge}
      </div>
      <h3>{_esc(f.title)}</h3>
      <p class="detail">{_esc(f.detail)}</p>
      {_evidence_chip(f.evidence)}
    </div>"""


def _supporting_row(f: Finding) -> str:
    return (
        f"<tr class='sev-{_esc(f.severity.value)}'>"
        f"<td><span class='sev-badge sev-{_esc(f.severity.value)}'>{_esc(f.severity.value.upper())}</span></td>"
        f"<td>{_esc(f.category.value)}</td>"
        f"<td><strong>{_esc(f.title)}</strong><br><span class='detail-inline'>{_esc(f.detail)}</span></td>"
        f"<td class='evidence-cell'>{_esc(defang(f.evidence))}</td>"
        "</tr>"
    )


def render_html(report: Report) -> str:
    verdict = report.verdict
    color = _VERDICT_HEX.get(verdict.label, "#8b949e")
    parsed = report.parsed
    key_evidence, supporting = _split_findings(report.findings)
    links = _suspicious_links(report.findings)

    details_html = "".join(
        f"<div class='detail-row'><span class='detail-label'>{_esc(label)}</span>"
        f"<span class='detail-value'>{_esc(defang(value) if label in ('From', 'Reply-To') else value)}</span></div>"
        for label, value in _message_details(parsed)
    )

    links_html = ""
    if links:
        items = "".join(
            f"<li><span class='link-chip'>{_esc(defang(f.evidence))}</span>"
            f"<span class='link-why'>{_esc(f.title)}</span></li>"
            for f in links
        )
        links_html = f"""
        <div class="alert-block">
          <h2>Suspicious / Malicious Link(s)</h2>
          <ul class="link-list">{items}</ul>
        </div>"""

    key_evidence_html = "".join(_key_evidence_card(f) for f in key_evidence) or (
        "<p class='muted'>No high-confidence indicators found.</p>"
    )
    supporting_html = "".join(_supporting_row(f) for f in supporting)
    supporting_section = ""
    if supporting:
        supporting_section = f"""
        <h2>Additional Signals ({len(supporting)})</h2>
        <p class="muted">Lower-confidence / supporting context - not individually enough to drive the verdict.</p>
        <table>
          <tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence (defanged)</th></tr>
          {supporting_html}
        </table>"""

    ioc_domains = "".join(f"<li>{_esc(defang(d))}</li>" for d in report.iocs.get("domains", []))
    ioc_urls = "".join(f"<li>{_esc(defang(u))}</li>" for u in report.iocs.get("urls", []))
    ioc_hashes = "".join(
        f"<li>{_esc(h['filename'])} - <span class='mono'>{_esc(h['sha256'])}</span></li>"
        for h in report.iocs.get("attachment_hashes", [])
    )

    ai_block = ""
    if report.ai_summary:
        ai_block = (
            "<div class='ai-summary'><h2>AI Summary <span class='muted'>(Claude)</span></h2>"
            f"<p>{_esc(report.ai_summary).replace(chr(10), '<br>')}</p></div>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishAnalyzer report - {_esc(parsed.subject) or 'no subject'}</title>
<style>
  :root {{
    --bg: #0d1117;
    --bg-elevated: #151b23;
    --border: #2d333b;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --accent: {color};
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    margin: 0; padding: 2.5rem;
    color: var(--text); background: var(--bg);
    line-height: 1.5;
  }}
  .wrap {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; font-weight: 600; margin: 0 0 1.25rem; letter-spacing: -0.01em; }}
  h2 {{ font-size: 1.05rem; font-weight: 600; margin: 2rem 0 0.5rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }}
  h3 {{ font-size: 1rem; margin: 0.6rem 0 0.4rem; }}
  p {{ margin: 0.4rem 0; }}
  .muted {{ color: var(--text-muted); font-size: 0.85rem; }}
  .mono {{ font-family: Consolas, "SF Mono", monospace; }}

  .verdict-banner {{
    display: flex; align-items: center; gap: 1rem;
    background: var(--bg-elevated); border: 1px solid var(--border); border-left: 5px solid var(--accent);
    border-radius: 8px; padding: 1.1rem 1.4rem; margin-bottom: 1.25rem;
  }}
  .verdict-label {{ font-size: 1.25rem; font-weight: 700; color: var(--accent); }}
  .verdict-meta {{ color: var(--text-muted); font-size: 0.85rem; margin-top: 0.15rem; }}

  .details-panel {{
    background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 8px;
    padding: 0.9rem 1.4rem; margin-bottom: 0.5rem;
  }}
  .detail-row {{ display: flex; padding: 0.3rem 0; border-bottom: 1px solid rgba(255,255,255,0.04); font-size: 0.9rem; }}
  .detail-row:last-child {{ border-bottom: none; }}
  .detail-label {{ width: 120px; flex-shrink: 0; color: var(--text-muted); }}
  .detail-value {{ word-break: break-word; }}

  .alert-block {{
    background: rgba(248, 81, 73, 0.08); border: 1px solid rgba(248, 81, 73, 0.4);
    border-radius: 8px; padding: 1rem 1.4rem; margin-top: 1.25rem;
  }}
  .alert-block h2 {{ border: none; margin-top: 0; color: #ff6b6b; }}
  .link-list {{ list-style: none; padding: 0; margin: 0.5rem 0 0; }}
  .link-list li {{ margin-bottom: 0.6rem; }}
  .link-chip {{
    display: block; font-family: Consolas, "SF Mono", monospace; font-size: 0.82rem;
    background: #1a1015; border: 1px solid rgba(248, 81, 73, 0.35); color: #ffb4b4;
    border-radius: 5px; padding: 0.4rem 0.6rem; word-break: break-all;
  }}
  .link-why {{ display: block; color: var(--text-muted); font-size: 0.8rem; margin-top: 0.15rem; }}

  .summary-panel {{
    background: var(--bg-elevated); border: 1px solid var(--border); border-left: 4px solid var(--accent);
    border-radius: 8px; padding: 1rem 1.4rem; white-space: pre-wrap; font-size: 0.92rem;
  }}

  .ai-summary {{
    background: var(--bg-elevated); border: 1px solid #3b4a6b; border-left: 4px solid #58a6ff;
    border-radius: 8px; padding: 1rem 1.4rem; margin-top: 1rem;
  }}
  .ai-summary h2 {{ border: none; margin: 0 0 0.4rem; color: #79c0ff; }}

  .card {{
    background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 8px;
    padding: 1rem 1.3rem; margin-top: 0.9rem; border-left-width: 4px;
  }}
  .card.sev-critical {{ border-left-color: #ff6b6b; }}
  .card.sev-high {{ border-left-color: #ff9f43; }}
  .card-head {{ display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.3rem; }}
  .sev-badge {{
    font-size: 0.7rem; font-weight: 700; letter-spacing: 0.03em; padding: 0.15rem 0.5rem; border-radius: 4px;
    text-transform: uppercase;
  }}
  .sev-badge.sev-critical {{ background: rgba(255,107,107,0.15); color: #ff6b6b; }}
  .sev-badge.sev-high {{ background: rgba(255,159,67,0.15); color: #ff9f43; }}
  .sev-badge.sev-medium {{ background: rgba(227,179,65,0.15); color: #e3b341; }}
  .sev-badge.sev-low {{ background: rgba(77,171,247,0.15); color: #4dabf7; }}
  .sev-badge.sev-info {{ background: rgba(139,148,158,0.15); color: #8b949e; }}
  .cat-badge {{
    font-size: 0.7rem; color: var(--text-muted); border: 1px solid var(--border); border-radius: 4px;
    padding: 0.15rem 0.5rem; text-transform: capitalize;
  }}
  .mitre {{
    font-size: 0.7rem; color: #79c0ff; border: 1px solid #3b4a6b; border-radius: 4px; padding: 0.15rem 0.5rem;
    font-family: Consolas, monospace;
  }}
  .card .detail {{ color: #c9d1d9; font-size: 0.9rem; margin: 0.3rem 0 0.6rem; }}
  .chip {{
    font-family: Consolas, "SF Mono", monospace; font-size: 0.82rem; word-break: break-all;
    background: #0a0d12; border: 1px solid var(--border); border-radius: 5px; padding: 0.5rem 0.7rem;
    color: #ffd166;
  }}

  table {{ border-collapse: collapse; width: 100%; margin-top: 0.75rem; background: var(--bg-elevated);
           border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th, td {{ border-bottom: 1px solid var(--border); padding: 0.6rem 0.7rem; text-align: left; vertical-align: top; font-size: 0.85rem; }}
  tr:last-child td {{ border-bottom: none; }}
  th {{ background: rgba(255,255,255,0.03); color: var(--text-muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; }}
  .detail-inline {{ color: var(--text-muted); font-size: 0.82rem; }}
  .evidence-cell {{ font-family: Consolas, "SF Mono", monospace; font-size: 0.78rem; word-break: break-all; color: #d2a8ff; }}

  ul {{ background: var(--bg-elevated); border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem 1.5rem; }}
  li {{ font-size: 0.85rem; }}

  .footer {{ margin-top: 2.5rem; color: var(--text-muted); font-size: 0.78rem; text-align: center; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>PhishAnalyzer Report</h1>

  <div class="verdict-banner">
    <div>
      <div class="verdict-label">{_esc(verdict.label)}</div>
      <div class="verdict-meta">score={verdict.score} &nbsp;|&nbsp; phishing_score={verdict.phishing_score} &nbsp;|&nbsp; confidence={_esc(verdict.confidence)}</div>
    </div>
  </div>

  <div class="details-panel">{details_html}</div>

  {links_html}

  {ai_block}

  <h2>Summary</h2>
  <div class="summary-panel">{_esc(verdict.summary)}</div>

  <h2>Key Evidence ({len(key_evidence)})</h2>
  <p class="muted">The specific findings that drive this verdict.</p>
  {key_evidence_html}

  {supporting_section}

  <h2>Indicators of Compromise (defanged)</h2>
  <p><strong>Domains</strong></p><ul>{ioc_domains or '<li>none</li>'}</ul>
  <p><strong>URLs</strong></p><ul>{ioc_urls or '<li>none</li>'}</ul>
  <p><strong>Attachment hashes (SHA-256)</strong></p><ul>{ioc_hashes or '<li>none</li>'}</ul>

  <p class="footer">Generated by PhishAnalyzer - static analysis only. No URLs were fetched, no domains were resolved, no attachments were opened.</p>
</div>
</body>
</html>
"""
