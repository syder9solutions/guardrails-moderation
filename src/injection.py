"""Prompt-injection detection — weighted signal scorer.

Covers the classic direct-override vectors plus the classes that keyword
filters miss:
  * role/JSON structural breaks (``</system>``, ``"role":"system"``)
  * instruction-exclusion phrases ("ignore previous instructions")
  * indirection ("repeat everything above", "translate but keep instructions")
  * Unicode smuggling — Unicode Tags block (U+E0000–U+E007F), zero-width
    chars, bidi overrides — invisible payloads the model still tokenizes
  * exfiltration scaffolding — markdown-image / URL-instruction combos
  * tool-use steering ("call the fetch tool with ...")

Decision rule: score >= threshold => flagged. Threshold tuned on the red-team
corpus AND a benign holdout (see tests) to keep the false-positive rate low.
"""

from __future__ import annotations

import re
import unicodedata

from .exceptions import Evidence

DEFAULT_INJECTION_THRESHOLD = 7

# (rule_id, weight, pattern, label)
_SIGNALS: list[tuple[str, int, re.Pattern[str], str]] = [
    ("INJ-override", 6,
     re.compile(
         r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|"
         r"preceding)\s+(?:instructions?|prompts?|directives?|rules?|messages?|"
         r"constraints?)\b"
         r"|\bdisregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+"
         r"(?:instructions?|prompts?|rules?|guardrails?|training)\b"
         r"|\bforget\s+(?:everything|all|your)\s+(?:above|before|prior|"
         r"instructions?|training)\b", re.I),
     "instruction-override phrasing"),
    ("INJ-newrole", 5,
     re.compile(
         r"\b(?:you\s+are\s+now|act\s+as\s+(?:if\s+you\s+are\s+)?(?:a|an)\b|"
         r"pretend\s+(?:you\s+are|to\s+be)\b|from\s+now\s+on\s+you\s+are\b|"
         r"enter\s+(?:developer|admin|root|god)\s+mode\b|"
         r"\bDAN\s+mode\b|do\s+anything\s+now\b)", re.I),
     "role-replacement / mode-escape attempt"),
    ("INJ-sysbreak", 6,
     re.compile(
         r"</\s*system\s*>|<\s*\|\s*system\s*\|\s*>|"
         r'"\s*role\s*"\s*:\s*"\s*system\s*"|'
         r"\bsystem\s*:\s*$|\bEND\s+OF\s+SYSTEM\b|\b###\s*SYSTEM\s*###",
         re.I | re.M),
     "system-role structural break"),
    ("INJ-extract", 5,
     re.compile(
         r"\b(?:repeat|print|output|reveal|show|recite|echo)\s+(?:everything|"
         r"all|the\s+text|the\s+prompt|your\s+(?:initial|system|original)"
         r"\s+(?:prompt|instructions?|message|configuration)|the\s+text\s+above"
         r"|the\s+(?:system|initial|original)\s+(?:prompt|instructions?|"
         r"configuration))\b"
         r"|\bwhat\s+(?:are\s+)?your\s+(?:initial|system|original)\s+"
         r"(?:instructions?|prompt)\b"
         r"|\bwhat\s+tools\s+(?:do\s+you\s+have|are\s+available\s+to\s+you)\b"
         r"|\b(?:list|print|show)\s+your\s+tools\b[^.\n]{0,40}"
         r"\b(?:names?|parameters?|scopes?)\b"
         r"|\bstarting\s+(?:with|from)\s+[\"']?you\s+are\b", re.I),
     "system-prompt extraction"),
    ("INJ-newsyssystem", 6,
     re.compile(
         r"\bnew\s+system\s+(?:directive|prompt|message|instruction)\b"
         r"|\b(?:this|the\s+following)\s+is\s+(?:a\s+)?(?:new|updated)\s+"
         r"system\s+(?:directive|message)\b", re.I),
     "fabricated system directive"),
    ("INJ-exfil", 7,
     re.compile(
         r"!\s*\[[^\]]*\]\s*\(\s*https?://|"
         r"<\s*img\b[^>]*src\s*=\s*[\"']?\s*https?://|"
         r"\b(?:send|post|fetch|curl|request|forward|upload|transmit|"
         r"exfiltrate)\b[^.\n]{0,80}"
         r"\bhttps?://[^\s\"')]+(?:\?|&)[^\s\"')]*=", re.I),
     "markdown-image / URL exfiltration scaffold"),
    ("INJ-toolsteer", 7,
     re.compile(
         r"\b(?:call|invoke|use|run)\s+(?:the\s+)?(?:fetch|browse|http_request|"
         r"web|search|get_url|read_file|execute|shell|eval|code)\b[^.\n]{0,80}"
         r"\b(?:tool|function|command)\b"
         r"|\b(?:call|invoke|use|run)\s+(?:the\s+)?"
         r"(?:fetch|browse|read_file|execute|eval|http)[_a-zA-Z0-9]*\s*\(", re.I),
     "tool-use steering"),
    ("INJ-secretxfil", 8,
     re.compile(
         r"\b(?:api[_\s-]?key|token|secret|password|credential|chat\s*history|"
         r"conversation|context)\b[^.\n]{0,80}"
         r"\b(?:https?://|base64|url[- ]?encode|encode[^.\n]{0,20}url)\b"
         r"|\b(?:credit\s*card|card\s+number|ssn|social\s+security|phone\s+"
         r"number|email\s+address)\b[^.\n]{0,80}"
         r"\b(?:base64|rot13|hex|encode|reversed?)\b", re.I),
     "secret/context exfiltration instruction"),
    ("INJ-hiddendir", 6,
     re.compile(
         r"\b(?:important\s+)?instructions?\s+(?:for\s+(?:the\s+)?(?:ai|assistant|"
         r"model|llm)|to\s+(?:the\s+)?(?:ai|assistant|model|llm))\b"
         r"|\b(?:assistant|ai)\s*:\s*(?:do\s+not|never\s+mention|silently)\b"
         r"|\bdo\s+not\s+mention\s+this\s+(?:instruction|message)\b"
         r"|\bwithout\s+(?:the\s+)?(?:user|them)\s+(?:noticing|knowing|seeing)\b",
         re.I),
     "hidden directive to the model"),
    ("INJ-encoding", 7,
     re.compile(
         r"\b(?:base64|rot13|hex|atbash|reversed?|backwards)\b[^.\n]{0,60}"
         r"\b(?:follow|execute|comply|obey|instructions?\s+(?:inside|within|"
         r"below))\b"
         r"|\bdecode\b[^.\n]{0,40}\b(?:then|and)\b[^.\n]{0,40}\b(?:do|follow|"
         r"execute|perform)\b", re.I),
     "encoded-instruction laundering"),
    ("INJ-indirect", 4,
     re.compile(
         r"\b(?:translate|summarize|rephrase)\b[^.\n]{0,60}"
         r"\b(?:but\s+)?(?:first|including|keeping)\b[^.\n]{0,60}"
         r"\b(?:instructions?|directions?|everything\s+above)\b"
         r"|\bwhen\s+(?:the\s+)?user\s+asks\b[^.\n]{0,40}\binstead\b", re.I),
     "indirection through benign task"),
    ("INJ-docdirective", 7,
     re.compile(
         # Retrieved content addressing the ASSISTANT directly ("Assistant
         # instruction: ...", "Note to the AI: ...") is the canonical indirect
         # injection shape. The existing INJ-* rules all expect an override or
         # an exfil verb, so a bare directive with a benign-looking encode/
         # append task scored 0 and reached the model.
         r"\b(?:assistant|ai|model|llm|chatbot|agent|bot)\s*"
         r"(?:instruction|instructions|directive|note|task|command|override)\s*:"
         r"|\b(?:note|message|instructions?)\s+(?:to|for)\s+the\s+"
         r"(?:ai|assistant|model|llm|chatbot|agent|bot)\b"
         r"|\byou\s+must\s+(?:base64|encode|append|send|post|forward|call|"
         r"include|embed)\b"
         r"|\b(?:base64|rot13|hex|url[- ]?encode)\b[^.\n]{0,60}"
         r"\b(?:and\s+)?(?:append|add|include|embed|prepend)\b"
         r"[^.\n]{0,40}\b(?:reply|response|answer|output)\b"
         r"|\bappend\s+(?:it\s+|them\s+)?to\s+your\s+(?:reply|response|"
         r"answer|output)\b",
         re.I),
     "document-directed instruction to the assistant"),
]


def _smuggling_evidence(text: str) -> list[Evidence]:
    """Unicode channels: Tags block, zero-width chars, bidi overrides."""
    found: list[Evidence] = []
    tags = [(i, c) for i, c in enumerate(text) if 0xE0000 <= ord(c) <= 0xE007F]
    if tags:
        found.append(Evidence(
            rule_id="INJ-unicode-tags",
            label=f"Unicode Tags block smuggling ({len(tags)} chars)",
            score=9,
            span=(tags[0][0], tags[-1][0] + 1),
            excerpt="…invisible payload…",
        ))
    zero_width = sum(1 for c in text if ord(c) in (0x200B, 0x200C, 0x200D, 0xFEFF))
    if zero_width >= 3:  # >=3 in one message is not typographic
        found.append(Evidence(
            rule_id="INJ-zero-width",
            label=f"zero-width character run ({zero_width})",
            score=7,
            span=(0, min(len(text), 1)),
            excerpt="…invisible payload…",
        ))
    if any(ord(c) in (0x202A, 0x202B, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)
           for c in text):
        found.append(Evidence(
            rule_id="INJ-bidi-override",
            label="bidi override control chars",
            score=7,
            span=(0, min(len(text), 1)),
            excerpt="…invisible payload…",
        ))
    return found


def _homoglyph_normalize(text: str) -> str:
    """Fold confusables so 'ígnore' doesn't dodge keyword signals."""
    out = []
    for ch in unicodedata.normalize("NFKD", text):
        if not unicodedata.combining(ch):
            out.append(ch)
    return "".join(out)


def scan_injection(
    text: str,
    threshold: int = DEFAULT_INJECTION_THRESHOLD,
) -> list[Evidence]:
    """Return evidence whose cumulative score meets/exceeds threshold.

    Returns all evidence anyway via :func:`scan_injection_all`; this entry
    point answers the policy question "does this cross the line?".
    """
    all_ev = scan_injection_all(text)
    total = sum(e.score for e in all_ev)
    return all_ev if total >= threshold else []


def scan_injection_all(text: str) -> list[Evidence]:
    """All injection evidence present, regardless of threshold."""
    normalized = _homoglyph_normalize(text)
    found: list[Evidence] = []
    for rule_id, weight, pattern, label in _SIGNALS:
        m = pattern.search(normalized)
        if m:
            found.append(Evidence(
                rule_id=rule_id,
                label=label,
                score=weight,
                span=m.span(),
                excerpt=_excerpt(normalized, *m.span()),
            ))
    found.extend(_smuggling_evidence(text))
    return found


def injection_score(text: str) -> int:
    """Cumulative weighted score of all injection signals in *text*."""
    return sum(e.score for e in scan_injection_all(text))


def _excerpt(text: str, start: int, end: int, width: int = 40) -> str:
    left = max(0, start - width)
    right = min(len(text), end + width)
    return (text[left:start] + "…" + text[end:right]).replace("\n", "\\n")
