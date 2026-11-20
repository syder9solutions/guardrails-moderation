"""PII detection & redaction — layered regex + validation.

Layers:
  1. High-precision format validators with checksums where available
     (Luhn for cards, format+rare-prefix checks for SSN/IBAN).
  2. Contextual regexes for emails, phones, IPs, MACs, API keys.
  3. A labeled-identifier heuristic ("Name:", "DOB:", "SSN:") that catches
     labeled fields without named-entity models.

Redaction preserves span-accurate replacement with typed placeholders so
downstream audit logs never hold raw PII.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .exceptions import Evidence

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def _luhn_ok(digits: str) -> bool:
    """Luhn checksum for card numbers."""
    if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
        return False
    total, dbl = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if dbl:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        dbl = not dbl
    return total % 10 == 0


def _ssn_ok(digits: str) -> bool:
    """SSN structural rules: area/group/serial constraints."""
    if len(digits) != 9:
        return False
    area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
    if area == 0 or area in (666, 900, 901, 902, 903, 904, 905, 906, 907,
                             908, 909, 910, 911, 912, 913, 914, 915, 916,
                             917, 918, 919, 920, 921, 922, 923, 924, 925,
                             926, 927, 928, 929, 930, 931, 932, 933, 934,
                             935, 936, 937, 938, 939, 940, 941, 942, 943,
                             944, 945, 946, 947, 948, 949, 950, 951, 952,
                             953, 954, 955, 956, 957, 958, 959, 960, 961,
                             962, 963, 964, 965, 966, 967, 968, 969, 970,
                             971, 972, 973, 974, 975, 976, 977, 978, 979,
                             980, 981, 982, 983, 984, 985, 986, 987, 988,
                             989, 990, 991, 992, 993, 994, 995, 996, 997,
                             998, 999):
        return False
    if group == 0 or serial == 0:
        return False
    return True


def _ssn_context_ok(text: str, match: "re.Match[str]") -> bool:
    """Reject 9-digit runs that are structurally not SSNs.

    Two things can look like an SSN and must not be redacted as one:

    * ZIP+4 (``10012-3456``) — nine digits with a separator, but the dash sits
      after five digits. A real SSN groups as 3-2-4, so alignment settles it.
    * The grouped forms themselves (``874-60-9123``, ``(874) 60-9123``) carry
      explicit SSN structure and are always accepted.

    A *bare* nine-digit run is genuinely ambiguous: ``Order 123456789`` and a
    real SSN have identical shape, and no context word reliably separates
    them. This control fails **closed** — a missed SSN is a reportable data
    exposure, while a redacted order number is visible and recoverable. The
    ambiguity is therefore resolved toward redaction, deliberately.
    """
    cand = match.group(0)
    groups = [g for g in re.split(r"[ ._()\-]+", cand) if g]
    if len(groups) > 1:
        return [len(g) for g in groups] == [3, 2, 4]
    return True


def _iban_ok(cand: str) -> bool:
    """Mod-97 IBAN validation (ISO 13616), tolerant of spaces."""
    s = re.sub(r"\s+", "", cand).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(num) % 97 == 1


# ---------------------------------------------------------------------------
# Matchers — each returns list of Evidence (span-relative to scanned text)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Matcher:
    rule_id: str
    label: str
    placeholder: str
    regex: re.Pattern[str]
    validator: Callable[[str], bool] | None = None
    #: Extra gate receiving (whole_text, match) — used where the *shape* alone
    #: is ambiguous and surrounding context must disambiguate.
    context_guard: Callable[[str, "re.Match[str]"], bool] | None = None


#: Words that mark an unstructured 9-digit run as an SSN. Kept for auditability
#: of the decision: the bare form is redacted unconditionally (fail-closed),
#: and this vocabulary documents which contexts make that unambiguous.
_SSN_CONTEXT = re.compile(
    r"\b(?:ssn|social\s+security|social\s+sec|taxpayer|tax\s+id|tin)\b",
    re.I)


_MATCHERS: list[_Matcher] = [
    _Matcher(
        "PII-EMAIL", "email address", "[EMAIL]",
        # RFC 5321 caps the local part at 64 octets; bounding it keeps the
        # match linear. The unbounded `[A-Za-z0-9._%+-]+@` form was O(n²):
        # on a 60 kB run of digits with no `@` it consumed to end-of-string
        # from every start offset and backtracked each time (~3 s). That is a
        # denial-of-service vector, since any user-supplied text reaches this
        # matcher.
        re.compile(
            r"\b[A-Za-z0-9._%+-]{1,64}@"
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
            r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*"
            r"\.[A-Za-z]{2,24}\b"
        ),
    ),
    _Matcher(
        "PII-SSN", "US SSN", "[SSN]",
        # Separator-tolerant: hyphen, space, dot, underscore, and the
        # parenthesised area-code form `(874) 60-9123` are all the same
        # identifier to a human, so they must be the same span to the
        # redactor. Validator receives the digits-only form.
        re.compile(
            r"(?<!\d)(?:\(\d{3}\)|\d{3})[ ._-]?\d{2}[ ._-]?\d{4}(?!\d)"
            r"|(?<!\d)\d{9}(?!\d)"
        ),
        _ssn_ok,
        _ssn_context_ok,
    ),
    _Matcher(
        "PII-CARD", "payment card", "[CARD]",
        re.compile(
            r"(?<!\d)(?:\d[ ._-]?){12,18}\d(?!\d)"
        ),
        _luhn_ok,
    ),
    _Matcher(
        "PII-IBAN", "IBAN", "[IBAN]",
        re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,8}\b"),
        _iban_ok,
    ),
    _Matcher(
        "PII-PHONE", "phone number", "[PHONE]",
        re.compile(
            r"(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"
        ),
    ),
    _Matcher(
        "PII-IPV4", "IPv4 address", "[IP]",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
    ),
    _Matcher(
        "PII-MAC", "MAC address", "[MAC]",
        re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"),
    ),
    _Matcher(
        "PII-APIKEY", "API key / bearer token", "[APIKEY]",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9]{20,}|Bearer\s+[A-Za-z0-9._-]{20,}"
            r"|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16})\b"
        ),
    ),
    _Matcher(
        "PII-DOB", "date of birth", "[DOB]",
        re.compile(
            r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-]"
            r"(?:19|20)\d{2}\b"
        ),
    ),
    _Matcher(
        "PII-PASSPORT", "passport number", "[PASSPORT]",
        re.compile(r"\b[A-Z]{1,2}\d{6,9}\b(?=\s*(?:passport|pass\b))", re.I),
    ),
]

# "Labeled field" heuristic: <Label>: <value> for labels that denote PII even
# when the value is free text (names, addresses). Value captured to line end.
_LABELED = re.compile(
    r"\b((?:full[ -]?name|first[ -]?name|last[ -]?name|name|address|"
    r"street[ -]?address|dob|date[ -]of[ -]birth|mother'?s[ -]?maiden[ -]?name)"
    r"\s*[:=]\s*)([^\n;]{2,120})",
    re.I,
)

# Redacting names by label: keep the label, mask the value.
_LABEL_VALUE = "REDACTED"


def _span(e: Evidence) -> tuple[int, int]:
    """Evidence spans are normalized non-None inside this module."""
    assert e.span is not None
    return e.span


def scan_pii(text: str) -> list[Evidence]:
    """Return all PII evidence spans in *text* (may overlap across rules)."""
    found: list[Evidence] = []
    for m in _MATCHERS:
        for match in m.regex.finditer(text):
            cand = match.group(0)
            if m.validator is not None and not m.validator(
                re.sub(r"[ ._()\-]", "", cand)
            ):
                continue
            if m.context_guard is not None and not m.context_guard(text, match):
                continue
            found.append(Evidence(
                rule_id=m.rule_id,
                label=m.label,
                score=10,
                span=match.span(),
                excerpt=_excerpt(text, match.start(), match.end()),
            ))
    for match in _LABELED.finditer(text):
        label, _ = match.group(1), match.group(2)
        start = match.start(2)
        found.append(Evidence(
            rule_id="PII-LABELED-FIELD",
            label=f"labeled PII field ({label.strip().rstrip(':=').strip()})",
            score=10,
            span=(start, match.end(2)),
            excerpt=_excerpt(text, start, match.end(2)),
        ))
    return found


def redact(text: str) -> tuple[str, list[Evidence]]:
    """Return (redacted_text, evidence). Non-overlapping, left-to-right."""
    evidence = scan_pii(text)
    # Sort by span start; drop evidence fully inside a previous span to avoid
    # double-masking (e.g. phone inside a labeled address value).
    ordered = sorted(
        evidence, key=lambda e: (_span(e)[0], -(_span(e)[1] - _span(e)[0]))
    )
    picked: list[Evidence] = []
    last_end = -1
    for e in ordered:
        if _span(e)[0] >= last_end:
            picked.append(e)
            last_end = _span(e)[1]

    out: list[str] = []
    cursor = 0
    for e in picked:
        out.append(text[cursor:_span(e)[0]])
        out.append(_placeholder_for(e))
        cursor = _span(e)[1]
    out.append(text[cursor:])
    return "".join(out), picked


def _placeholder_for(e: Evidence) -> str:
    for m in _MATCHERS:
        if m.rule_id == e.rule_id:
            return m.placeholder
    return "[REDACTED]"  # labeled-field heuristic


def _excerpt(text: str, start: int, end: int, width: int = 24) -> str:
    """Safe excerpt: never includes the raw match itself."""
    left = max(0, start - width)
    right = min(len(text), end + width)
    return (text[left:start] + "…" + text[end:right]).replace("\n", "\\n")
