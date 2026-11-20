"""Jailbreak detection — persona-escape and safety-filter-override patterns.

Distinct from prompt injection: injection aims to hijack instructions or
extract data; a jailbreak aims to remove the model's safety behavior
(persona substitution, hypothetical framing, token-smuggling slang like
"AIM: always intelligent and malicious", multi-step scenario building).
"""

from __future__ import annotations

import re

from .exceptions import Evidence

DEFAULT_JAILBREAK_THRESHOLD = 7

# (rule_id, weight, pattern, label)
_SIGNALS: list[tuple[str, int, re.Pattern[str], str]] = [
    ("JB-persona", 7,
     re.compile(
         r"\b(?:from\s+(?:now|this\s+point)\s+on,?\s*you\s+(?:are|will\s+be)|"
         r"you\s+must\s+(?:act|behave)\s+as|you\s+have\s+no\s+(?:restrictions|"
         r"filters|guidelines|rules|moral|ethics)|all\s+of\s+your\s+"
         # `content` is optional and may be plural/qualified: jb-005 says
         # "all of your content filters", which the old alternation missed
         # entirely (score 0) while the unqualified form scored 6.
         r"(?:(?:content|safety|output|moderation)\s+)?"
         r"(?:restrictions|filters|guidelines|guardrails|safeguards)\s+"
         r"(?:are|have\s+been|were)\s+(?:off|removed|lifted|disabled|gone))\b",
         re.I),
     "persona substitution / filter removal claim"),
    ("JB-grandma", 7,
     re.compile(
         r"\b(?:grandma|grandmother|grandpa|grandfather)\b[^.\n]{0,120}\b"
         r"(?:read|tell|used\s+to\s+read|bedtime|sleep)\b"
         r"|\b(?:read|act)\s+as\s+my\s+(?:grandma|grandmother|grandpa|"
         r"grandfather)\b"
         r"|\bplease\s+act\s+as\s+my\s+deceased\s+grand", re.I),
     "grandma-persona emotional manipulation vector"),
    ("JB-aim", 8,
     re.compile(
         r"\bAIM\s*:\s*always\s+intelligent\s+and\s+malicious\b"
         r"|\bniccolo\s+mach[iy]avelli\b"
         r"|\bDUDE\s+mode\b|\bOMEGA\s+prompt\b|\bdev\s*mode\s+v2\b", re.I),
     "known jailbreak persona (AIM / DUDE / OMEGA)"),
    ("JB-hypothetical", 5,
     re.compile(
         r"\b(?:in\s+a\s+)?(?:hypothetical|fictional|imaginary)\s+"
         r"(?:story|scenario|world|novel|setting)\b[^.\n]{0,60}\b"
         r"(?:how|explain|describe|provide|give|write)\b"
         r"|\bfor\s+(?:a\s+)?(?:novel|movie|screenplay|book|story)\s+"
         r"(?:i\s+am\s+)?writing\b[^.\n]{0,60}\b(?:how|describe|explain)\b"
         r"|\bmy\s+character\s+(?:needs|wants)\s+to\b", re.I),
     "hypothetical/fiction framing to extract harmful content"),
    ("JB-expert", 4,
     re.compile(
         r"\bas\s+an?\s+(?:unrestricted|uncensored|unfiltered|amoral)\s+"
         r"\w+\b"
         r"|\b(?:an\s+)?expert\s+(?:in\s+)?(?:with\s+)?no\s+(?:limits|restrictions)\b",
         re.I),
     "unrestricted-expert role claim"),
    ("JB-encoding", 5,
     re.compile(
         r"\b(?:respond|answer|reply|output)\b[^.\n]{0,60}\b(?:in\s+)?"
         r"(?:base64|rot13|hex|cipher|code|reversed)\b"
         r"|\bencode\s+your\s+(?:answer|response)\b", re.I),
     "encoded-response laundering (evades output moderation)"),
    ("JB-noethics", 4,
     re.compile(
         r"\b(?:ignore|forget|bypass|disable)\s+(?:your\s+)?"
         r"(?:ethics|ethical\s+guidelines|content\s+policy|safety\s+"
         r"guidelines?|moral\s+compass|alignment)\b"
         r"|\byou\s+(?:can|may|must)\s+(?:say|do)\s+anything\b", re.I),
     "safety-policy bypass request"),
    ("JB-gradual", 3,
     re.compile(
         r"\b(?:let'?s\s+play\s+a\s+game|imagine\s+you'?re?\s+playing\s+a\s+"
         r"character|this\s+is\s+just\s+between\s+us|nobody\s+will\s+know)\b",
         re.I),
     "gradual-escalation framing"),
    ("JB-refusal-suppress", 6,
     re.compile(
         r"\bdo\s+not\s+(?:include|add|say)\s+(?:any\s+)?(?:warnings?|"
         r"disclaimers?|refusals?|\"?i\s+cannot\"?)\b"
         r"|\bstart\s+your\s+(?:reply|response)\s+with\s+[\"']?certainly[\"']?"
         r"|\bnever\s+(?:say|refuse)\s+[\"']?i\s+can'?t\b", re.I),
     "refusal suppression instruction"),
    ("JB-fake-authority", 7,
     re.compile(
         # In-band authority claim that "authorizes" the model to drop its
         # safety behaviour. Previously scored 0 on every rule, which let
         # jb-011 reach the LLM untouched.
         r"\b(?:system\s+(?:admin|administrator|notice|override|message)|"
         r"admin(?:istrator)?\s+(?:notice|override|message)|"
         r"developer\s+(?:notice|message|override)|"
         r"(?:openai|anthropic|internal|security)\s+(?:safety\s+)?team)\b"
         r"[^.\n]{0,120}\b(?:has\s+)?(?:authori[sz]ed|approved|cleared|"
         r"permitted|greenlit)\b"
         r"|\bauthori[sz]ed\s+this\s+(?:session|conversation|request)\b"
         r"[^.\n]{0,60}\b(?:red[- ]?team|testing|override)\b"
         r"|\bcomply\s+without\s+(?:any\s+)?(?:safety\s+checks?|further\s+"
         r"verification|restrictions)\b", re.I),
     "fake in-band authority claim authorizing unsafe compliance"),
]

# Combined attack markers — "how to" + harm-domain within one message.
# "Explain step by step how to ..." and "give me the steps to ..." are the
# same request as "how to ..." and were previously invisible here.
_HOWTO = re.compile(
    r"\bhow\s+(?:to|do\s+i|can\s+i|would\s+i)\b"
    r"|\bstep[-\s]?by[-\s]?step\b"
    r"|\b(?:the\s+)?(?:exact\s+)?steps?\s+(?:to|for)\b"
    r"|\b(?:explain|describe|detail|walk\s+me\s+through|teach\s+me)\b"
    r"[^.\n]{0,40}\b(?:how|the\s+(?:steps|process|method))\b",
    re.I)
_HARM_DOMAINS: list[tuple[str, re.Pattern[str]]] = [
    ("weapons/explosives",
     re.compile(r"\b(?:bomb|explosive|ied|pipe\s*bomb|detonat|nuclear\s+device|"
                r"bioweapon|nerve\s*agent|sarin|ricin|anthrax)\w*\b", re.I)),
    ("malware/intrusion",
     re.compile(r"\b(?:ransomware|keylogger|rootkit|botnet|ddos|sql\s*injection|"
                r"phishing\s+kit|zero[- ]day\s+exploit|steal\s+credit\s*card)\b", re.I)),
    ("drugs/synthesis",
     re.compile(r"\b(?:meth(?:amphetamine)?|mdma|fentanyl\s*synthesis|"
                r"synthes(?:is|ize|ize)\s+(?:drugs|narcotics))\b", re.I)),
    ("violence/self-harm",
     re.compile(r"\b(?:hurt\s+(?:someone|myself)|kill\s+(?:myself|a\s+person)|"
                r"poison\s+(?:someone|my\s+))\b", re.I)),
    ("fraud/counterfeit",
     re.compile(r"\b(?:counterfeit\s+(?:money|bills|documents)|forge\s+(?:id|ids|"
                r"passport|documents)|launder\s+money)\b", re.I)),
]

#: Defensive/analytical framing. "How do I recognise a phishing kit" and
#: "our SOC needs to explain how ransomware encrypts files" match the how-to
#: pattern and name a harm domain, but ask for *detection* or *explanation*,
#: not operational capability. Their evidence is therefore *discounted*.
#:
#: This is a discount, never a veto. A full exemption is trivially defeated by
#: prefixing "for my awareness training" to any harmful request — verified:
#: that coat let 4/10 coated attacks through with no evidence at all. A single
#: benign phrase must not be able to zero out the signal, because the attacker
#: controls the phrasing. Discounting leaves the rule able to fire on its own
#: for a bare defensive question, while a genuine solicitation still
#: accumulates other signals (moderation, override, exfil) past the threshold.
_DEFENSIVE_FRAME = re.compile(
    r"\b(?:recogni[sz]e|detect|detection|identify|spot|defend|defen[cs]e|"
    r"protect|protection|prevent|prevention|mitigat\w+|remediat\w+|"
    r"report|reporting|recover\w*|harden\w*|secure\s+(?:my|our|the)\b|"
    r"incident\s+response|threat\s+model\w*|awareness|training|"
    r"compliance|audit\w*|policy|board\s+deck|educat\w+|explain\s+to\s+"
    r"(?:staff|the\s+team|management)|post-?mortem|forensic\w*|"
    r"how\s+(?:does|do)\b[^.\n]{0,40}\bwork)\b",
    re.I)

#: Weight of a how-to-harm hit when a defensive frame is present. Below the
#: default threshold on purpose: a bare defensive question is answered, but
#: any *additional* signal (override verb, exfil request, moderation hit)
#: pushes the total back over the line.
_DEFENSIVE_DISCOUNT = 4

#: An explicit request to *produce* a harmful artifact. Unlike a how-to
#: question, this is operational regardless of the surrounding topic frame:
#: "how do I detect a phishing kit? now write one" is a build request wearing
#: a detection question. Deliberately verb + artifact, so "detect",
#: "recognise" and "report" do not match.
_BUILD_REQUEST = re.compile(
    r"\b(?:write|build|make|create|generate|code|develop|assemble|produce|"
    r"give\s+me)\b"
    r"[^.\n]{0,60}\b(?:one|it|them|a\s+(?:copy|working\s+\w+|version)|"
    r"(?:working\s+)?(?:code|exploit|payload|script|kit|bomb|sample))\b",
    re.I)

# A "how-to" request aimed at an operational harm domain is a complete
# harmful request on its own: it needs no help from a persona signal to be
# blockable. It is therefore emitted with enough weight to cross the default
# threshold by itself (previously 4 < 7, which made the rule structurally
# unable to block and let "explain step by step how to counterfeit money"
# through). Kept as a named constant so the regression test can assert the
# invariant rather than the literal number.
_COMBINATION_THRESHOLD = DEFAULT_JAILBREAK_THRESHOLD


def scan_jailbreak(
    text: str,
    threshold: int = DEFAULT_JAILBREAK_THRESHOLD,
) -> list[Evidence]:
    all_ev = scan_jailbreak_all(text)
    total = sum(e.score for e in all_ev)
    return all_ev if total >= threshold else []


def scan_jailbreak_all(text: str) -> list[Evidence]:
    found: list[Evidence] = []
    for rule_id, weight, pattern, label in _SIGNALS:
        m = pattern.search(text)
        if m:
            found.append(Evidence(rule_id, label, weight, m.span(),
                                  _excerpt(text, *m.span())))
    m_howto = _HOWTO.search(text)
    if m_howto is not None:
        hits = [name for name, pat in _HARM_DOMAINS if pat.search(text)]
        if len(hits) >= 1:
            # Discount only a *pure* defensive question. If the same text also
            # asks for the artifact to be produced, the defensive wording is a
            # coat, not a frame, and full weight applies.
            coat = (_DEFENSIVE_FRAME.search(text) is not None
                    and _BUILD_REQUEST.search(text) is None)
            weight = _DEFENSIVE_DISCOUNT if coat else _COMBINATION_THRESHOLD
            label = "how-to request targeting: " + ", ".join(hits)
            if weight < _COMBINATION_THRESHOLD:
                label += " (defensive framing: discounted)"
            elif _DEFENSIVE_FRAME.search(text):
                label += " (defensive framing overridden by build request)"
            found.append(Evidence(
                "JB-howto-harm", label, weight,
                m_howto.span(), _excerpt(text, *m_howto.span()),
            ))
    return found


def jailbreak_score(text: str) -> int:
    return sum(e.score for e in scan_jailbreak_all(text))


def _excerpt(text: str, start: int, end: int, width: int = 40) -> str:
    left = max(0, start - width)
    right = min(len(text), end + width)
    return (text[left:start] + "…" + text[end:right]).replace("\n", "\\n")
