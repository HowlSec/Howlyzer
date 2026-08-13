# PhishAnalyzer

A local, offline-first triage tool for emails your users report as phishing.
Drop in a `.eml`/`.msg` file (or a whole folder of them) and get back a clear
verdict — **Phishing**, **Spam / Unwanted**, **Suspicious**, or **Likely
Legitimate** — with the specific evidence behind it, in seconds, without
sending anything anywhere.

## Why this exists — and what it deliberately does *not* do

Every check here is **static**: it reads the email file as text and bytes.
Nothing in this tool ever fetches a URL, resolves a domain, or opens/executes
an attachment. That's a deliberate safety boundary, not an oversight — a
triage tool that "clicks the link to check" is itself a liability (tips off
the attacker, can trigger tracking, could hit something genuinely dangerous).
If you need to safely detonate a URL or file, that's a separate, sandboxed
job for something like a sandbox/VM or a threat-intel API — this tool tells
you *what's worth doing that for*, and gives you the exact IOCs to feed in.

## Security guarantees

This tool exists specifically to be pointed at malicious content, so its own
safety matters more than most. What's actually enforced, not just claimed:

- **No network calls to anything in the email.** No URL is ever fetched, no
  domain is ever resolved, no attachment is ever opened or executed. This
  isn't just a design intention — `tests/test_no_unsafe_network_calls.py`
  scans the entire codebase for `webbrowser`, `subprocess`, `os.system`,
  `requests`/`httpx` calls, raw sockets, `eval`/`exec`, etc., and fails the
  build if any of them show up outside the one intentional exception (the
  optional Claude API call, which only ever talks to Anthropic's API — never
  to anything derived from the email).
- **Links are never clickable in the report.** Every URL/domain shown in the
  HTML report is plain, defanged text (`hxxps://evil[.]tk`, not a real
  scheme) — never an `<a href>`. Opening the report cannot open a link.
- **The HTML report can't run anything, even if a bug slips through.** Every
  attacker-controlled value (subject, sender name, filenames, evidence
  strings) is HTML-escaped before being embedded. On top of that, the report
  ships a strict Content-Security-Policy (`script-src 'none'`,
  `connect-src 'none'`, `object-src 'none'`, ...) so even a future escaping
  bug couldn't turn into working script execution or an outbound request —
  defense in depth, not reliance on one layer.
- **The console can't be crashed by a crafted email.** Subject lines and
  attachment filenames are attacker-controlled and can contain arbitrary
  Unicode. Windows' legacy console (`cmd.exe`) uses a limited codepage and
  will raise `UnicodeEncodeError` — crashing the whole run — on characters
  outside it; the CLI reconfigures stdout/stderr to degrade unencodable
  characters to a placeholder instead of dying mid-report.
- **The optional AI summary is hardened against prompt injection.** Sender
  names, subjects, and finding text derived from the email are sent to
  Claude wrapped in explicit `<untrusted_findings>` delimiters, with the
  system prompt directly instructing it to treat everything inside as data
  only — never as instructions — regardless of what it claims to be.
- **Oversized files are rejected before being read into memory** (50 MB
  cap) rather than risking memory exhaustion on a pathological input.

**Known residual risk, by design tradeoff:** `.msg` parsing depends on the
third-party [`extract-msg`](https://github.com/TeamMsgExtractor/msg-extractor)
library to handle Outlook's proprietary binary format — like any parser
handling untrusted binary input, a bug there is a bug this tool inherits.
Keep it updated (`pip install -U extract-msg`). Legacy `.doc`/`.xls`/`.ppt`
macro content is flagged by extension only, not deeply parsed (see
Limitations below) — that's a coverage gap, not a code-execution risk, since
nothing is ever opened regardless.

## What it checks

- **Authentication & alignment** — SPF/DKIM/DMARC results from the
  `Authentication-Results` header; From vs Reply-To vs Return-Path domain
  mismatches (a classic "route replies to an attacker mailbox" tell); a
  body signed with a name that has nothing to do with the actual sending
  identity (pretexting — technically clean headers, real webmail account,
  but "signed" by someone else entirely); a From display name shaped like
  a date rather than a person/org (bulk-account artifact).
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
`.eml` (RFC822) format that every mail provider on Earth can export — so it
works regardless of which mailbox the report came from. Quick reference:

| Provider | Menu path | Saves as |
|---|---|---|
| Outlook desktop | Drag the message onto a folder/the `analyze.bat` shortcut, **or** open it → **File → Save As** | `.msg` |
| Outlook web (outlook.com) | Open message → **···** → **View → View message source** (or **Download** if shown) | `.eml` |
| Gmail | Open message → **⋮** → **Show original** → **Download original** | `.eml` |
| ProtonMail (web) | Open message → **⋯** (More) → **Export** | `.eml` |
| Yahoo Mail | Open message → **More** (**···**) → **View raw message**, then save the page as `.eml`, or forward as attachment (see below) | `.eml` |
| Apple Mail (macOS) | Select message → **File → Save As** → format **Raw Message Source** | `.eml` |
| Thunderbird | Select message → **File → Save As → File**, or drag onto a folder | `.eml` |
| Any other webmail/client | Look for **"View source"**, **"Show original"**, **"Download message"**, or **"Export"** — it's virtually always one of those four | `.eml` |

Full steps for the three most common ones:

**Outlook (desktop app)**
1. Drag the message out of Outlook onto a folder or the `analyze.bat`
   shortcut — Outlook exports it as `.msg` automatically on drop, or
2. Open it → **File → Save As** → keep the default **Outlook Message Format
   (.msg)** → Save.

**Gmail**
1. Open the message → click **⋮** (three dots, top-right of the opened
   message).
2. Click **Show original**.
3. On the page that opens, click **Download Original** near the top.
4. That's your `.eml` — use **Show original → Download Original** specifically
   (not just "Download message" if both appear), since it's the true raw
   source with full headers, which is what the SPF/DKIM/DMARC checks need.

**ProtonMail (web, mail.proton.me)**
1. Open the message → click **⋯** (More, top-right).
2. Click **Export**.
3. Choose a save location — saves as `.eml`.
   ([Proton's own docs](https://proton.me/support/export-import-emails))

**Any provider, if the report reaches you forwarded**
- If a colleague forwards the suspicious email *with the original message
  attached* (not just forwarded inline as quoted text), save/drag out that
  attachment instead of analyzing the forwarding wrapper — always ask
  reporters to forward as an attachment when possible. This is what actually
  matters for accuracy: the SPF/DKIM/DMARC and sender-alignment checks only
  mean something against the *original* headers. A forwarded-inline copy has
  your coworker's headers, not the attacker's, and will under-report.

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
tests/                        # includes test_no_unsafe_network_calls.py — the safety-guarantee test
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
- Files over 50 MB are rejected outright (see Security guarantees above) —
  if you legitimately need to analyze something larger, raise
  `MAX_FILE_SIZE_BYTES` in `phishanalyzer/parser.py`.
- This is one input into your decision-making, not a final verdict — treat
  "Suspicious" as "go look," not "definitely fine."

## License

[MIT](LICENSE) — use it, fork it, adapt it for your own org's brands and
language freely.
