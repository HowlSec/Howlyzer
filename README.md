# PhishAnalyzer

A local, offline-first triage tool for emails your users report as phishing.
Drop in a `.eml`/`.msg` file (or a whole folder of them) and get back a clear
verdict — **Phishing**, **Spam / Unwanted**, **Suspicious**, or **Likely
Legitimate** — with the specific evidence behind it, in seconds, without
sending anything anywhere.

Built after reading [this write-up](https://medium.com/@techalisa/i-built-a-phishing-triage-copilot-with-claude-ai-cyber-defense-ops-review-thoughts-on-vibe-coding-6a2b41b0efc8)
about a Claude-based phishing triage copilot; this is a from-scratch local
implementation of the same idea, adapted to answer "phishing or just spam?"
specifically, and to run entirely on your own Windows machine.

## Why this exists — and what it deliberately does *not* do

Every check here is **static**: it reads the email file as text and bytes.
Nothing in this tool ever fetches a URL, resolves a domain, or opens/executes
an attachment. That's a deliberate safety boundary, not an oversight — a
triage tool that "clicks the link to check" is itself a liability (tips off
the attacker, can trigger tracking, could hit something genuinely dangerous).
If you need to safely detonate a URL or file, that's a separate, sandboxed
job for something like a sandbox/VM or a threat-intel API — this tool tells
you *what's worth doing that for*, and gives you the exact IOCs to feed in.

## What it checks

- **Authentication & alignment** — SPF/DKIM/DMARC results from the
  `Authentication-Results` header; From vs Reply-To vs Return-Path domain
  mismatches (a classic "route replies to an attacker mailbox" tell).
- **Brand impersonation** — sender display name claims to be a known brand
  (PayPal, Microsoft, your bank, etc.) while the actual domain isn't theirs;
  same check applied to links. Fully editable — see below.
- **Links** — every URL in the plain-text and HTML body: raw-IP links, URL
  shorteners, punycode/homograph domains, high-abuse TLDs, credential-harvest
  paths (`/login`, `/verify-account`, ...), the `user@host` URL trick,
  excessively nested subdomains, lookalike/typosquat domains (edit-distance
  against known brands), and **visible link text that doesn't match where the
  link actually goes** — one of the strongest single signals there is.
- **Attachments** — dangerous extensions (.exe/.scr/.js/.hta/...),
  macro-enabled Office formats, double extensions (`invoice.pdf.exe`), and
  password-protected zip archives. Every attachment is SHA-256 hashed.
- **Content** — urgency/pressure phrasing, generic greetings, Business Email
  Compromise-style financial-request language (wire transfers, gift cards,
  "updated banking details"), and HTML tricks used to hide text from the
  reader while keeping it machine-readable (zero-width characters,
  white-on-white/`display:none` styling).

Findings are mapped to [MITRE ATT&CK](https://attack.mitre.org/) technique
IDs where applicable (e.g. `T1566.002` Spearphishing Link, `T1566.001`
Spearphishing Attachment) so they slot into existing incident documentation.

## Phishing vs. Spam — how the verdict is decided

Every finding contributes to an overall score, but findings are also tagged
as either a **phishing signal** (credential theft, malware delivery, targeted
fraud, active brand impersonation) or not (generic urgency copy, a bare
generic greeting — things just as common in ordinary bulk marketing). The
verdict compares both:

| Verdict | Roughly means |
|---|---|
| **Likely Legitimate** | Score ≤ 14. Nothing meaningfully off. |
| **Spam / Unwanted** | Score ≥ 15, but driven by bulk/marketing-style signals, not credential-theft/malware/fraud indicators. |
| **Suspicious** | Real phishing-flavored signal present, but not overwhelming — worth a human look. |
| **Phishing** | Phishing-tagged score ≥ 40 — strong, specific evidence of credential theft, malware delivery, or targeted fraud. |
| **Malicious — High Confidence** | Any CRITICAL finding (e.g. confirmed brand impersonation, an executable attachment) or phishing score ≥ 80. |

This is a heuristic tool for **triage**, not a verdict of record — it tells
you where to spend your attention first, not a substitute for judgment on
ambiguous cases.

## Installation (Windows)

**Requirements:** Python 3.10+ ([python.org/downloads](https://www.python.org/downloads/) —
check "Add python.exe to PATH" during install).

1. Clone or download this repo.
2. Open PowerShell in the folder and run:
   ```powershell
   .\setup.ps1
   ```
   This creates a `.venv` virtual environment and installs everything needed
   (including `.msg`/Outlook support).

If PowerShell blocks the script from running (unsigned script policy), run:
```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

## Usage

### Fastest: drag and drop

Drag a `.eml` or `.msg` file straight onto **`analyze.bat`**. A console
window opens with the verdict, and a JSON + HTML report is written to
`reports\` next to the script — the HTML report is self-contained and safe
to attach to a ticket or forward to a colleague (every URL/domain in it is
already defanged, e.g. `hxxps://evil[.]tk`).

### Command line

```powershell
# Single file, verdict printed to the console
.\.venv\Scripts\python.exe -m phishanalyzer path\to\reported_email.eml

# A whole folder of reported emails at once
.\.venv\Scripts\python.exe -m phishanalyzer C:\Users\you\Downloads\reported

# Also write JSON + HTML reports
.\.venv\Scripts\python.exe -m phishanalyzer email.eml --format all --output-dir reports

# Skip the optional AI summary even if you have a key set
.\.venv\Scripts\python.exe -m phishanalyzer email.eml --no-ai
```

Try it right now against the bundled samples:
```powershell
.\.venv\Scripts\python.exe -m phishanalyzer samples\sample_phish.eml
.\.venv\Scripts\python.exe -m phishanalyzer samples\sample_spam.eml
.\.venv\Scripts\python.exe -m phishanalyzer samples\sample_legitimate.eml
```

**Exit codes** (useful for scripting/automation): `0` = legitimate or spam,
`1` = suspicious, `2` = phishing or malicious.

### Where to get the `.eml`/`.msg` file from

PhishAnalyzer reads both Outlook's native `.msg` format and the universal
`.eml` (RFC822) format that Gmail, ProtonMail, and every other mail provider
can export — so it works regardless of which mailbox the report came from.

**Outlook (desktop app)**
- Drag the message out of Outlook onto a folder/the `analyze.bat` shortcut —
  saves as `.msg` automatically, or
- Open it → **File → Save As** → keep the default **Outlook Message Format
  (.msg)**.

**Outlook (web / outlook.com)**
- Open the message → **...** (More actions) → **View → View message
  source**, or use the **Download** option if shown — saves as `.eml`.

**Gmail**
- Open the message → **⋮** (three dots, top right of the message) →
  **Show original** → **Download original** — saves as `.eml` with full
  original headers (this is the one you want for SPF/DKIM/DMARC checks to
  work — it's the raw source, not a re-rendered copy).
- A simpler **Download message** option is sometimes available directly in
  the same **⋮** menu — also produces a usable `.eml`.

**ProtonMail (web, mail.proton.me)**
- Open the message → **⋯** (More) → **Export** → choose a save location —
  saves as `.eml`. ([Proton's own docs](https://proton.me/support/export-import-emails))

**Any provider, if forwarded to you as an attachment**
- If a colleague forwards the suspicious email *with the original attached*
  (not just forwarded inline), save/drag out that attachment instead of the
  forwarding wrapper — always ask reporters to forward as an attachment when
  possible, since that's what preserves the original headers this tool
  actually checks.

## Optional: AI-written executive summary (Claude)

Fully optional — the tool is complete and useful without it. If you set an
Anthropic API key, PhishAnalyzer additionally sends the *already-extracted
findings* (never the raw email, never anything that would cause a link to be
rendered or fetched) to Claude for a short plain-English summary and
recommended action.

```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
.\.venv\Scripts\python.exe -m phishanalyzer email.eml
```

Set it permanently for your user account:
```powershell
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "sk-ant-...", "User")
```
(Open a new PowerShell window afterward for it to take effect.)

## Customizing for your organization

Edit `phishanalyzer\indicators.json` — it's the whole knowledge base, no code
changes needed:

- `impersonated_brands` — add your own bank, your company's own domain
  (catches internal-lookalike attacks), SaaS vendors you use, etc. Format is
  `"Brand Name": ["real-domain.com", "other-real-domain.com"]`.
- `urgency_keywords`, `financial_bec_keywords`, `generic_greetings` — add
  phrases specific to your language/region (the article that inspired this
  tool did exactly this for Bulgarian-language phishing).
- `suspicious_tlds`, `url_shorteners`, `credential_harvest_paths` — tuned
  defaults, extend as you see new patterns.

Point at a different file instead of editing the bundled one:
```powershell
.\.venv\Scripts\python.exe -m phishanalyzer email.eml --indicators C:\path\to\my_indicators.json
```
or set `PHISHANALYZER_INDICATORS` as an environment variable.

## Project structure

```
phishanalyzer/
  parser.py          # .eml / .msg -> normalized ParsedEmail (headers, body, links, attachments)
  analyzers/
    headers.py        # SPF/DKIM/DMARC, From/Reply-To/Return-Path alignment, brand impersonation
    urls.py            # link/IP static analysis
    attachments.py     # extension risk, macros, double extensions, encrypted zips
    content.py          # urgency language, BEC phrasing, hidden-text tricks
  scoring.py          # findings -> verdict
  report.py            # console (rich) / JSON / self-contained defanged HTML
  llm.py                 # optional Claude executive summary
  iocs.py                 # IOC extraction + defanging
  indicators.json          # editable knowledge base
  cli.py                    # command-line interface
samples/                     # synthetic phishing / spam / legitimate examples used by tests
tests/
setup.ps1                      # Windows installer
analyze.bat                     # drag-and-drop launcher
```

## Running the tests

```powershell
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest tests\ -v
```

## Limitations

- Legacy `.doc`/`.xls`/`.ppt` macro presence is flagged by extension only
  (can't confirm macros without deeper static parsing — see
  [oletools](https://github.com/decalage2/oletools) for that).
  `.docm`/`.xlsm`/`.pptm` (definitely macro-*capable*) are flagged directly.
- Domain-comparison logic uses a simple last-two-labels heuristic, not a full
  public-suffix list — it's deliberately conservative (more likely to
  under-flag on multi-part ccTLDs like `.co.uk` than to false-positive).
- This is one input into your decision-making, not a final verdict — treat
  "Suspicious" as "go look," not "definitely fine."
