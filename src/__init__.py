"""Guardrails & Moderation — a layered safety system for LLM applications.

Layers:
    pii        — regex + Luhn PII detection/redaction (emails, SSNs, phones, cards, IPs, IBANs)
    injection  — prompt-injection signal scorer (direct + indirect channels, unicode smuggling)
    jailbreak  — persona/filter-override detector
    moderation — content-policy classifier (harmful solicitation, toxicity)
    policy     — central decision engine (allow / redact / transform / block / escalate)
    pipeline   — composes input guard -> LLM -> output guard with bounded repair loop
    tools      — least-privilege tool registry with HITL gating (defense-in-depth)
    api        — FastAPI guarded /v1/chat proxy + baseline /v1/chat/unguarded
"""

__version__ = "1.0.0"
