"""Central policy engine — composes all detectors into one decision.

Decision model:
    allow      pass through unmodified
    redact     sanitize PII and forward the sanitized text
    transform  model sees de-fanged text (unicode-normalized), user sees
               model output
    block      refuse at the boundary (no LLM call)
    escalate   flag for human-in-the-loop review (high-stakes gating)

Every decision carries full evidence for auditability. Thresholds are
env-tunable (GUARDRAILS_INJECTION_THRESHOLD etc.) but default conservative.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum

from . import jailbreak, moderation, pii
from .config import load_dotenv
from .exceptions import Evidence
from .injection import injection_score, scan_injection_all

load_dotenv()  # .env may tune thresholds via env


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


INJECTION_THRESHOLD = _env_int("GUARDRAILS_INJECTION_THRESHOLD", 7)
JAILBREAK_THRESHOLD = _env_int("GUARDRAILS_JAILBREAK_THRESHOLD", 7)
ESCALATION_THRESHOLD = _env_int("GUARDRAILS_ESCALATION_THRESHOLD", 14)


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "guardrails.redact"
    TRANSFORM = "guardrails.transform"
    BLOCK = "guardrails.block"
    ESCALATE = "guardrails.escalate"


@dataclass
class ChannelVerdict:
    channel: str
    action: Action
    score: int
    evidence: list[Evidence] = field(default_factory=list)
    redacted_text: str | None = None

    def to_dict(self) -> dict:
        return {
            "channel": self.channel,
            "action": self.action.value,
            "score": self.score,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class PolicyDecision:
    action: Action
    channels: list[ChannelVerdict]
    summary: str
    redacted_text: str | None = None

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "summary": self.summary,
            "redacted_text": self.redacted_text,
            "channels": [c.to_dict() for c in self.channels],
        }


def _normalize_unicode(text: str) -> str:
    """De-fang smuggling channels: strip Tags-block/zero-width/bidi chars
    so the model never sees the invisible payload."""
    cleaned = []
    for ch in text:
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            continue
        if cp in (0x200B, 0x200C, 0x200D, 0xFEFF,
                  0x202A, 0x202B, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
            continue
        cleaned.append(ch)
    return "".join(cleaned)


def evaluate_input(text: str) -> PolicyDecision:
    """Full input-side evaluation across all detectors."""
    channels: list[ChannelVerdict] = []

    # --- moderation (hard block) -------------------------------------------
    mod_ev = moderation.scan_moderation(text)
    if mod_ev:
        channels.append(ChannelVerdict(
            channel="moderation", action=Action.BLOCK,
            score=max(e.score for e in mod_ev), evidence=mod_ev,
        ))
        return PolicyDecision(
            action=Action.BLOCK, channels=channels,
            summary=f"blocked: {mod_ev[0].label}",
        )

    # --- jailbreak (hard block at threshold) --------------------------------
    jb_ev = jailbreak.scan_jailbreak(text, threshold=JAILBREAK_THRESHOLD)
    if jb_ev:
        channels.append(ChannelVerdict(
            channel="jailbreak", action=Action.BLOCK,
            score=sum(e.score for e in jb_ev), evidence=jb_ev,
        ))
        return PolicyDecision(
            action=Action.BLOCK, channels=channels,
            summary=f"blocked: {jb_ev[0].label}",
        )

    # --- prompt injection ---------------------------------------------------
    inj_ev = scan_injection_all(text)
    inj_total = injection_score(text)
    if inj_total >= INJECTION_THRESHOLD:
        channels.append(ChannelVerdict(
            channel="injection", action=Action.BLOCK,
            score=inj_total, evidence=inj_ev,
        ))
        return PolicyDecision(
            action=Action.BLOCK, channels=channels,
            summary=f"blocked: prompt injection (score {inj_total})",
        )

    # --- unicode smuggling below threshold: transform -----------------------
    smuggle_ev = [e for e in inj_ev
                  if e.rule_id in ("INJ-unicode-tags", "INJ-zero-width",
                                   "INJ-bidi-override")]
    if smuggle_ev:
        channels.append(ChannelVerdict(
            channel="injection-smuggling", action=Action.TRANSFORM,
            score=sum(e.score for e in smuggle_ev), evidence=smuggle_ev,
        ))
        # smuggling alone below threshold: still de-fang before the model
        return PolicyDecision(
            action=Action.TRANSFORM, channels=channels,
            summary="transformed: invisible unicode payload stripped",
            redacted_text=_normalize_unicode(text),
        )

    # --- PII redaction -------------------------------------------------------
    redacted, pii_ev = pii.redact(text)
    if pii_ev:
        channels.append(ChannelVerdict(
            channel="pii", action=Action.REDACT,
            score=len(pii_ev), evidence=pii_ev, redacted_text=redacted,
        ))
        return PolicyDecision(
            action=Action.REDACT, channels=channels,
            summary=f"redacted {len(pii_ev)} PII span(s)",
            redacted_text=redacted,
        )

    # --- clean ---------------------------------------------------------------
    channels.append(ChannelVerdict(
        channel="clean", action=Action.ALLOW, score=0,
    ))
    return PolicyDecision(
        action=Action.ALLOW, channels=channels, summary="no signals",
    )


def evaluate_output(
    text: str,
    *,
    injected_content: bool = False,
) -> PolicyDecision:
    """Output-side evaluation: PII leakage, on-policy check, residual
    injection reflections, and toxic output."""
    channels: list[ChannelVerdict] = []

    # harmful content that leaked through the model
    mod_ev = moderation.scan_moderation(text)
    if mod_ev:
        channels.append(ChannelVerdict(
            channel="moderation", action=Action.BLOCK,
            score=max(e.score for e in mod_ev), evidence=mod_ev,
        ))
        return PolicyDecision(
            action=Action.BLOCK, channels=channels,
            summary=f"output blocked: {mod_ev[0].label}",
        )

    jail_ev = jailbreak.scan_jailbreak(text, threshold=JAILBREAK_THRESHOLD)
    if jail_ev:
        channels.append(ChannelVerdict(
            channel="jailbreak", action=Action.BLOCK,
            score=sum(e.score for e in jail_ev), evidence=jail_ev,
        ))
        return PolicyDecision(
            action=Action.BLOCK, channels=channels,
            summary=f"output blocked: {jail_ev[0].label}",
        )

    # PII must never leave through the output path
    redacted, pii_ev = pii.redact(text)
    if pii_ev:
        channels.append(ChannelVerdict(
            channel="pii", action=Action.REDACT,
            score=len(pii_ev), evidence=pii_ev, redacted_text=redacted,
        ))

    # untrusted-content markers must never be reflected into output
    if injected_content:
        inj_ev = scan_injection_all(text)
        if inj_ev:
            channels.append(ChannelVerdict(
                channel="injection-reflection", action=Action.BLOCK,
                score=sum(e.score for e in inj_ev), evidence=inj_ev,
            ))
            return PolicyDecision(
                action=Action.BLOCK, channels=channels,
                summary="output blocked: injected instruction reflected",
            )

    if channels:
        return PolicyDecision(
            action=channels[0].action, channels=channels,
            summary=f"output {channels[0].action.value}",
            redacted_text=redacted if pii_ev else None,
        )

    channels.append(ChannelVerdict(
        channel="clean", action=Action.ALLOW, score=0,
    ))
    return PolicyDecision(
        action=Action.ALLOW, channels=channels, summary="output clean",
    )
