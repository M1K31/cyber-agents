"""Sensitive data redaction for PII, PHI (health), and PCI/financial telemetry.

Applied before threat logs or event text are passed to the local analyst model,
stored in triage timelines, or exported into authority/forensic handoff profiles.
"""
from __future__ import annotations

import re
from typing import Any

# PII patterns
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)"
)

# PHI / Health patterns (HIPAA identifiers)
_PHI_MRN_RE = re.compile(
    r"\b(?:MRN|medical[_ -]?record(?:[_ -]?(?:no|num|number|id))?|patient[_ -]?id)"
    r"\s*[:#=\-]\s*[A-Za-z0-9-]{4,24}\b",
    re.IGNORECASE,
)
_PHI_ICD_RE = re.compile(
    r"\b(?:diagnosis|icd-?10)\s*[:=]\s*[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b",
    re.IGNORECASE,
)

# Financial / PCI patterns
_PAN_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_BANK_ACCT_RE = re.compile(
    r"\b(?:routing|aba|account|acct|swift|iban)(?:[_ -]?(?:no|num|number|id))?"
    r"\s*[:#=\-]\s*[A-Za-z0-9-]{6,34}\b",
    re.IGNORECASE,
)


def _luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def redact_sensitive_data(text: str) -> tuple[str, dict[str, int]]:
    """Scrub PII, PHI (health), and financial/PCI identifiers from text.

    Returns ``(redacted_text, counts)`` where ``counts`` maps redacted category
    names to the number of replacements made.
    """
    if not text:
        return "", {}

    counts: dict[str, int] = {}

    def _sub(pattern: re.Pattern[str], placeholder: str, category: str, src: str) -> str:
        n = 0

        def _repl(_m: re.Match[str]) -> str:
            nonlocal n
            n += 1
            return placeholder

        out = pattern.sub(_repl, src)
        if n:
            counts[category] = counts.get(category, 0) + n
        return out

    result = str(text)

    # 1. Credit card PANs (Luhn-verified to avoid false positives on timestamps/IDs)
    pan_hits = 0

    def _pan_repl(match: re.Match[str]) -> str:
        nonlocal pan_hits
        raw = match.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if _luhn_valid(digits):
            pan_hits += 1
            return "[REDACTED_PAN]"
        return raw

    result = _PAN_CANDIDATE_RE.sub(_pan_repl, result)
    if pan_hits:
        counts["financial_pan"] = pan_hits

    # 2. Bank / routing / IBAN identifiers
    result = _sub(_BANK_ACCT_RE, "[REDACTED_FINANCIAL]", "financial_account", result)

    # 3. PHI / Health identifiers
    result = _sub(_PHI_MRN_RE, "[REDACTED_PHI]", "phi_identifier", result)
    result = _sub(_PHI_ICD_RE, "[REDACTED_PHI_DIAGNOSIS]", "phi_diagnosis", result)

    # 4. PII (SSN, email, phone)
    result = _sub(_SSN_RE, "[REDACTED_SSN]", "pii_ssn", result)
    result = _sub(_EMAIL_RE, "[REDACTED_EMAIL]", "pii_email", result)
    result = _sub(_PHONE_RE, "[REDACTED_PHONE]", "pii_phone", result)

    return result, counts


def redact_structure(value: Any) -> tuple[Any, dict[str, int]]:
    """Recursively redact sensitive strings inside dicts/lists."""
    totals: dict[str, int] = {}

    def _merge(c: dict[str, int]) -> None:
        for k, v in c.items():
            totals[k] = totals.get(k, 0) + v

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            redacted, c = redact_sensitive_data(node)
            _merge(c)
            return redacted
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        return node

    return _walk(value), totals
