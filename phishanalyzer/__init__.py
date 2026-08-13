"""PhishAnalyzer — local, static phishing/spam triage for reported emails.

Everything in this package operates on the email file only: no URL is
fetched, no domain is resolved, and no attachment is opened or executed.
Analysis is entirely offline unless the optional AI summary is enabled.
"""

__version__ = "0.1.0"
