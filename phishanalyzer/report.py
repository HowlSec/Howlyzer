"""Console, JSON, and self-contained HTML report rendering.

The HTML report escapes every piece of attacker-controlled text (subject,
sender name, finding evidence, etc.) before embedding it, and defangs every
URL/domain — the report itself must be safe to open in a browser and safe
to paste into chat/ticketing tools without anything becoming clickable.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .iocs import defang
from .models import Report

_VERDICT_COLOR = {
    "Likely Legitimate": "green",
    "Spam / Unwanted": "yellow",
    "Suspicious": "dark_orange",
    "Phishing": "red",
    "Malicious — High Confidence": "bold red",
}

_VERDICT_HEX = {
    "Likely Legitimate": "#2e7d32",
    "Spam / Unwanted": "#b8860b",
    "Suspicious": "#e65100",
    "Phishing": "#c62828",
    "Malicious — High Confidence": "#8e0000",
}

_SEVERITY_COLOR = {
    "info": "grey62",
    "low": "cyan",
    "medium": "yellow",
    "high": "orange3",
    "critical": "bold red",
}


def render_console(report: Report) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:
        _render_console_plain(report)
        return

    console = Console()
    verdict = report.verdict
    color = _VERDICT_COLOR.get(verdict.label, "white")

    console.print(
        Panel(
            f"[{color}]{verdict.label}[/{color}]\n"
            f"score={verdict.score}  phishing_score={verdict.phishing_score}  confidence={verdict.confidence}",
            title=report.parsed.source_path,
            expand=False,
        )
    )

    if report.findings:
        table = Table(title="Findings", show_lines=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Category", no_wrap=True)
        table.add_column("Finding")
        table.add_column("Evidence", overflow="fold")
        for f in sorted(report.findings, key=lambda x: x.severity.value, reverse=True):
            sev_color = _SEVERITY_COLOR.get(f.severity.value, "white")
            table.add_row(
                f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}]",
                f.category.value,
                f"{f.title}\n[dim]{f.detail}[/dim]",
                f.evidence,
            )
        console.print(table)
    else:
        console.print("[green]No indicators triggered.[/green]")

    console.print(f"\n[bold]Summary:[/bold]\n{report.ai_summary or verdict.summary}")

    if report.ai_summary:
        console.print("[dim](AI-generated summary via Claude)[/dim]")


def _render_console_plain(report: Report) -> None:
    verdict = report.verdict
    print(f"=== {report.parsed.source_path} ===")
    print(f"Verdict: {verdict.label}  (score={verdict.score}, phishing_score={verdict.phishing_score}, "
          f"confidence={verdict.confidence})")
    print()
    if report.findings:
        for f in sorted(report.findings, key=lambda x: x.severity.value, reverse=True):
            print(f"[{f.severity.value.upper()}] {f.category.value}: {f.title}")
            print(f"    {f.detail}")
            if f.evidence:
                print(f"    evidence: {f.evidence}")
    else:
        print("No indicators triggered.")
    print()
    print("Summary:")
    print(report.ai_summary or verdict.summary)


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


def _esc(value: str) -> str:
    import html as _html

    return _html.escape(str(value), quote=True)


def render_html(report: Report) -> str:
    verdict = report.verdict
    color = _VERDICT_HEX.get(verdict.label, "#444")
    parsed = report.parsed

    rows = []
    for f in sorted(report.findings, key=lambda x: x.severity.value, reverse=True):
        rows.append(
            f"<tr class='sev-{_esc(f.severity.value)}'>"
            f"<td>{_esc(f.severity.value.upper())}</td>"
            f"<td>{_esc(f.category.value)}</td>"
            f"<td><strong>{_esc(f.title)}</strong><br><span class='detail'>{_esc(f.detail)}</span></td>"
            f"<td class='evidence'>{_esc(defang(f.evidence))}</td>"
            f"<td>{_esc(f.mitre or '')}</td>"
            "</tr>"
        )
    findings_html = "\n".join(rows) or "<tr><td colspan='5'>No indicators triggered.</td></tr>"

    ioc_domains = "".join(f"<li>{_esc(defang(d))}</li>" for d in report.iocs.get("domains", []))
    ioc_urls = "".join(f"<li>{_esc(defang(u))}</li>" for u in report.iocs.get("urls", []))
    ioc_hashes = "".join(
        f"<li>{_esc(h['filename'])} — {_esc(h['sha256'])}</li>" for h in report.iocs.get("attachment_hashes", [])
    )

    ai_block = ""
    if report.ai_summary:
        ai_block = (
            "<h2>AI Summary (Claude)</h2>"
            f"<p class='summary'>{_esc(report.ai_summary).replace(chr(10), '<br>')}</p>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PhishAnalyzer report — {_esc(parsed.subject) or 'no subject'}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }}
  .verdict {{ display:inline-block; padding: 0.5rem 1rem; border-radius: 6px; color: #fff; background: {color}; font-weight: 600; font-size: 1.1rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; background: #fff; }}
  th, td {{ border: 1px solid #ddd; padding: 0.5rem; text-align: left; vertical-align: top; font-size: 0.9rem; }}
  th {{ background: #f0f0f0; }}
  .detail {{ color: #555; font-size: 0.85rem; }}
  .evidence {{ font-family: Consolas, monospace; font-size: 0.8rem; word-break: break-all; }}
  .sev-critical td:first-child {{ color: #8e0000; font-weight: 700; }}
  .sev-high td:first-child {{ color: #c62828; font-weight: 700; }}
  .sev-medium td:first-child {{ color: #b8860b; font-weight: 700; }}
  .sev-low td:first-child {{ color: #1565c0; }}
  .meta {{ color: #555; margin: 0.25rem 0; }}
  .summary {{ background: #fff; border-left: 4px solid {color}; padding: 1rem; white-space: pre-wrap; }}
  ul {{ background: #fff; padding: 0.75rem 1.5rem; border: 1px solid #ddd; }}
  code {{ background: #eee; padding: 0.1rem 0.3rem; border-radius: 3px; }}
</style>
</head>
<body>
  <h1>PhishAnalyzer Report</h1>
  <p class="verdict">{_esc(verdict.label)}</p>
  <p class="meta">score={verdict.score} &nbsp; phishing_score={verdict.phishing_score} &nbsp; confidence={_esc(verdict.confidence)}</p>
  <p class="meta"><strong>File:</strong> {_esc(parsed.source_path)}</p>
  <p class="meta"><strong>Subject:</strong> {_esc(parsed.subject)}</p>
  <p class="meta"><strong>From:</strong> {_esc(parsed.from_display)} &lt;{_esc(defang(parsed.from_addr))}&gt;</p>

  {ai_block}

  <h2>Summary</h2>
  <p class="summary">{_esc(verdict.summary)}</p>

  <h2>Findings ({len(report.findings)})</h2>
  <table>
    <tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence (defanged)</th><th>MITRE</th></tr>
    {findings_html}
  </table>

  <h2>Indicators of Compromise (defanged)</h2>
  <p><strong>Domains</strong></p><ul>{ioc_domains or '<li>none</li>'}</ul>
  <p><strong>URLs</strong></p><ul>{ioc_urls or '<li>none</li>'}</ul>
  <p><strong>Attachment hashes (SHA-256)</strong></p><ul>{ioc_hashes or '<li>none</li>'}</ul>

  <p class="meta">Generated by PhishAnalyzer — static analysis only, no URLs were fetched or domains resolved.</p>
</body>
</html>
"""
