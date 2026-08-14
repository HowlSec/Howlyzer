"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, analyzers, llm, report, scoring
from .indicators import load_indicators
from .iocs import extract_iocs
from .models import Report
from .parser import load_email

_EXIT_BY_LABEL = {
    "Likely Legitimate": 0,
    "Spam / Unwanted": 0,
    "Suspicious": 1,
    "Phishing": 2,
    "Malicious - High Confidence": 2,
}

_EMAIL_EXTENSIONS = {".eml", ".msg"}


def _default_reports_dir() -> Path:
    """The 'reports' folder next to the installed tool, not the caller's cwd.

    A plain string default of "reports" would resolve relative to whatever
    directory the command happens to be invoked from, scattering reports
    across random folders depending on where the user's shell was sitting.
    Anchoring to this file's own location means the report always lands in
    the same place - <wherever this repo/install lives>/reports - regardless
    of cwd, matching what analyze.bat/analyze.sh already do explicitly.
    """
    return Path(__file__).resolve().parent.parent / "reports"


def analyze_file(path: Path, indicators: dict, use_ai: bool = True) -> Report:
    parsed = load_email(path)
    findings = analyzers.run_all(parsed, indicators)
    verdict = scoring.build_verdict(findings)
    iocs = extract_iocs(parsed)

    ai_summary = None
    if use_ai and llm.available():
        ai_summary = llm.summarize(parsed, verdict, findings)

    return Report(parsed=parsed, findings=findings, verdict=verdict, iocs=iocs, ai_summary=ai_summary)


def _iter_input_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(p for p in target.iterdir() if p.suffix.lower() in _EMAIL_EXTENSIONS)
    raise FileNotFoundError(f"No such file or directory: {target}")


def _write_outputs(rep: Report, out_dir: Path, formats: set[str]) -> Path | None:
    """Write the requested report file(s). Returns the HTML report's path, if written."""
    stem = Path(rep.parsed.source_path).stem
    if "json" in formats:
        (out_dir / f"{stem}.json").write_text(report.to_json(rep), encoding="utf-8")
    html_path = None
    if "html" in formats:
        html_path = out_dir / f"{stem}.html"
        html_path.write_text(report.render_html(rep), encoding="utf-8")
    return html_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishanalyzer",
        description="Static, local triage for reported phishing/spam emails (.eml / .msg).",
    )
    parser.add_argument("path", help="Path to a .eml/.msg file, or a directory of them")
    parser.add_argument(
        "--format",
        choices=["console", "json", "html", "all"],
        default="console",
        help="Output format(s) printed/written in addition to the always-on HTML report. "
        "'all' also writes a JSON report to --output-dir.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to write the report(s) into (default: a 'reports' folder next to "
        "the installed tool, regardless of the current working directory)",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip writing the HTML report (by default one is always written after analysis)",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip the optional Claude summary even if ANTHROPIC_API_KEY is set",
    )
    parser.add_argument(
        "--indicators",
        default=None,
        help="Path to a custom indicators.json (default: bundled indicators.json, "
        "or PHISHANALYZER_INDICATORS env var)",
    )
    parser.add_argument("--version", action="version", version=f"phishanalyzer {__version__}")
    return parser


def _harden_console_encoding() -> None:
    """Never let attacker-controlled Unicode crash the console.

    Subject lines, display names, and attachment filenames come straight
    from the (untrusted) email and can contain arbitrary Unicode. Windows'
    legacy console (cmd.exe without UTF-8 mode) uses a limited codepage
    (e.g. cp1252) and raises UnicodeEncodeError on anything outside it,
    which would otherwise crash mid-report on a specially crafted email.
    Reconfiguring with errors="replace" makes unencodable characters
    degrade to a placeholder instead of killing the process. No-op on
    platforms/terminals that are already UTF-8 (the normal case).
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _harden_console_encoding()
    args = build_parser().parse_args(argv)
    target = Path(args.path)

    try:
        files = _iter_input_files(target)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not files:
        print(f"error: no .eml/.msg files found in {target}", file=sys.stderr)
        return 2

    indicators = load_indicators(args.indicators)
    out_dir = Path(args.output_dir) if args.output_dir else _default_reports_dir()
    formats = {"json", "html"} if args.format == "all" else {args.format}
    if not args.no_html:
        formats.add("html")
    formats &= {"json", "html"}
    show_console = args.format in ("console", "all")

    if formats:
        out_dir.mkdir(parents=True, exist_ok=True)

    worst_exit = 0
    for path in files:
        try:
            rep = analyze_file(path, indicators, use_ai=not args.no_ai)
        except Exception as exc:
            print(f"error analyzing {path}: {exc}", file=sys.stderr)
            worst_exit = max(worst_exit, 2)
            continue

        if show_console:
            report.render_console(rep)
            if len(files) > 1:
                print()

        html_path = _write_outputs(rep, out_dir, formats)
        if html_path is not None:
            print(f"HTML report: {html_path}")

        worst_exit = max(worst_exit, _EXIT_BY_LABEL.get(rep.verdict.label, 1))

    return worst_exit


if __name__ == "__main__":
    raise SystemExit(main())
