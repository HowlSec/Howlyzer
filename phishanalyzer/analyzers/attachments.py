"""Static attachment triage: extension risk, macro-capable formats, double
extensions, encrypted archives. Nothing is ever extracted, opened, or executed
- attachments were already read as raw bytes once, during parsing, purely to
compute their size and SHA-256."""

from __future__ import annotations

import io
import zipfile

from ..models import Attachment, Category, Finding, ParsedEmail, Severity

_DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".msi", ".msp", ".jar",
    ".lnk", ".iso", ".img", ".cpl", ".gadget", ".application", ".reg", ".vhd",
    ".vhdx", ".chm",
}

_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}
_LEGACY_OFFICE_EXTENSIONS = {".doc", ".xls", ".ppt", ".rtf"}

_ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar"}


def _ext(filename: str) -> str:
    filename = filename.lower()
    idx = filename.rfind(".")
    return filename[idx:] if idx != -1 else ""


def _all_extensions(filename: str) -> list[str]:
    parts = filename.lower().split(".")
    return [f".{p}" for p in parts[1:]] if len(parts) > 1 else []


def _zip_is_encrypted(att: Attachment) -> bool | None:
    """Return True if a .zip attachment has an encrypted entry, None if unknown.

    Uses zipfile purely to read the central directory / local headers -
    nothing is ever decompressed or extracted.
    """
    if not att.raw:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(att.raw)) as zf:
            return any(info.flag_bits & 0x1 for info in zf.infolist())
    except Exception:
        return None


def analyze(parsed: ParsedEmail, indicators: dict) -> list[Finding]:
    findings: list[Finding] = []

    for att in parsed.attachments:
        ext = _ext(att.filename)
        all_exts = _all_extensions(att.filename)

        if ext in _DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    category=Category.ATTACHMENT,
                    severity=Severity.CRITICAL,
                    title=f"Executable/script attachment ({ext})",
                    detail=f"'{att.filename}' is a directly executable or script file type. "
                    "Legitimate business correspondence essentially never delivers this way.",
                    evidence=f"{att.filename}  sha256={att.sha256}",
                    mitre="T1566.001",
                )
            )
        elif ext in _MACRO_EXTENSIONS:
            findings.append(
                Finding(
                    category=Category.ATTACHMENT,
                    severity=Severity.HIGH,
                    title=f"Macro-enabled Office document ({ext})",
                    detail=f"'{att.filename}' is a macro-enabled Office format. A very common "
                    "malware delivery vector via 'Enable Content' social engineering.",
                    evidence=f"{att.filename}  sha256={att.sha256}",
                    mitre="T1566.001",
                )
            )
        elif ext in _LEGACY_OFFICE_EXTENSIONS:
            findings.append(
                Finding(
                    category=Category.ATTACHMENT,
                    severity=Severity.LOW,
                    title=f"Legacy Office document ({ext})",
                    detail=f"'{att.filename}' can carry VBA macros; this cannot be confirmed "
                    "without deeper static analysis (see tools like oletools/olevba). "
                    "Flagged for awareness, not confirmed malicious.",
                    evidence=f"{att.filename}  sha256={att.sha256}",
                    phishing_signal=False,
                )
            )

        if len(all_exts) >= 2 and all_exts[-1] in _DANGEROUS_EXTENSIONS:
            findings.append(
                Finding(
                    category=Category.ATTACHMENT,
                    severity=Severity.CRITICAL,
                    title="Double extension used to disguise an executable",
                    detail=f"'{att.filename}' ends in a dangerous extension after what looks "
                    "like a document/image extension - a classic trick since Windows often "
                    "hides the real (final) extension by default.",
                    evidence=att.filename,
                    mitre="T1036.007",
                )
            )

        if ext == ".zip":
            encrypted = _zip_is_encrypted(att)
            if encrypted:
                findings.append(
                    Finding(
                        category=Category.ATTACHMENT,
                        severity=Severity.HIGH,
                        title="Password-protected/encrypted zip attachment",
                        detail=(
                            f"'{att.filename}' contains an encrypted entry (its contents "
                            "could not be listed without the password). This is a well-known "
                            "technique to smuggle malware past mail-gateway AV scanning - "
                            "especially suspicious if the password appears in the email body."
                        ),
                        evidence=f"{att.filename}  sha256={att.sha256}",
                        mitre="T1027.002",
                    )
                )
            else:
                findings.append(
                    Finding(
                        category=Category.ATTACHMENT,
                        severity=Severity.LOW,
                        title="Zip archive attachment",
                        detail=f"'{att.filename}' is a .zip archive. Not encrypted, but "
                        "archive contents were not enumerated in this pass - check separately "
                        "if further review is warranted.",
                        evidence=f"{att.filename}  sha256={att.sha256}",
                        phishing_signal=False,
                    )
                )
        elif ext in (".7z", ".rar"):
            findings.append(
                Finding(
                    category=Category.ATTACHMENT,
                    severity=Severity.MEDIUM,
                    title=f"Uncommon archive format ({ext})",
                    detail=f"'{att.filename}' uses an archive format less common in everyday "
                    "business mail; sometimes chosen specifically because default AV/gateway "
                    "scanning has weaker coverage for it than for .zip.",
                    evidence=f"{att.filename}  sha256={att.sha256}",
                )
            )

    return findings
