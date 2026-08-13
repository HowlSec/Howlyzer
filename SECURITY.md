# Security Policy

PhishAnalyzer is a static analysis tool for reported phishing/spam emails.
It's designed to be pointed at malicious content, so its own security matters
more than most tools — see the "Security guarantees" section in the
[README](README.md) for what's already enforced (no network calls to
anything in the email, no clickable links in reports, escaped/CSP-hardened
HTML output, crash-resistant console handling, prompt-injection-hardened AI
summary, file-size limits) and how those guarantees are tested.

## Reporting a vulnerability

If you find a way to make this tool do something it shouldn't — fetch a URL,
execute an attachment, leak data, crash in an unhandled way on a crafted
input, break out of the HTML report's sandboxing, or anything else that
violates the guarantees in the README — please report it privately rather
than opening a public issue:

- Preferred: use GitHub's [private vulnerability reporting](https://github.com/HowlSec/Howlyzer/security/advisories/new)
  for this repository (Security tab → Report a vulnerability).

Please include:
- The crafted `.eml`/`.msg` (or a minimal reproduction) that triggers it
- What you expected vs. what actually happened
- Impact, as you understand it (e.g. "this fetches an attacker URL despite
  the no-network-calls guarantee")

## Scope

In scope: anything in this repository. The one intentional, documented
exception to "no network calls" is the *optional* AI summary feature, which
talks only to Anthropic's API when you provide your own `ANTHROPIC_API_KEY` —
that's expected behavior, not a vulnerability, unless it can be made to
contact something other than Anthropic's API or leak more than the
structured findings it's designed to send.

Third-party dependencies (`rich`, `extract-msg`, `anthropic`) have their own
upstream security processes — please report issues in those libraries
directly to their maintainers. Dependabot is enabled on this repo to track
known vulnerabilities in them.
