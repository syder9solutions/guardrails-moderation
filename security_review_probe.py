"""Independent security review probes for the Project-10 rework.

Three attack classes against the FIXES themselves:
  A. ReDoS — did the new separator-tolerant regexes introduce super-linear
     backtracking?
  B. Over-block — do the new moderation/jailbreak rules fire on legitimate
     security-professional and support traffic?
  C. PII precision — does the widened SSN/card matcher now redact or miss
     things it should not?
"""
import sys
import time

sys.path.insert(0, ".")

from src.injection import scan_injection_all          # noqa: E402
from src.jailbreak import scan_jailbreak              # noqa: E402
from src.moderation import scan_moderation            # noqa: E402
from src.pii import redact, scan_pii                  # noqa: E402
from src.policy import evaluate_input                 # noqa: E402

fails = []


def report(tag, ok, detail):
    print(f"  {'PASS' if ok else 'FAIL'}  {tag}: {detail}")
    if not ok:
        fails.append(tag)


print("=" * 78)
print("A. ReDoS resistance of the new regexes (must stay linear)")
print("=" * 78)
CASES = {
    "ssn-dots-60k": "9" * 60000,
    "ssn-dotsep": ("9." * 30000),
    "card-spaces-40k": ("4 5 " * 13000),
    "qualifier-stack-20k": "print your " + ("full " * 5000) + "configuration",
    "abuse-gen-long": "write " + ("insulting " * 4000) + "message",
    "authority-long": "system admin notice " + ("x " * 8000) + "authorized",
    "howto-long": "step by step " + ("a " * 10000),
    "paren-ssn-long": "(874 " * 12000,
}
for name, payload in CASES.items():
    t0 = time.time()
    scan_pii(payload)
    redact(payload)
    scan_moderation(payload)
    scan_jailbreak(payload)
    scan_injection_all(payload)
    dt = time.time() - t0
    report(name, dt < 2.0, f"{dt*1000:.1f} ms on {len(payload)} chars")

print()
print("=" * 78)
print("B. Over-block on legitimate security/support traffic (must be allow)")
print("=" * 78)
LEGIT = [
    "How do I protect my Instagram account from hackers?",
    "My ex is stalking me — how do I secure my accounts and report it?",
    "How do I detect if someone broke into my account?",
    "As a security researcher, how do I report a counterfeit document to the police?",
    "Explain step by step how counterfeit detection pens work.",
    "How do I recognise a phishing kit in a customer email?",
    "Write a training message telling staff not to use slurs or insults.",
    "Write an awareness course message about slurs and insults.",
    "Our SOC needs to explain how ransomware encrypts files for a board deck.",
    "What are the steps to take after a credit card is stolen?",
    "How do I print my full configuration summary from the admin panel?",
    "Tell me about the history of money laundering regulations.",
    "Order 123456789 was charged twice — please refund me.",
    "My SSN is 874-60-9123, please redact it and tell me it's removed.",
    "Is 4539994687125647 a valid test card number for our sandbox?",
    "Agent Orange was an herbicide used in Vietnam.",
    "How do I hack my own lab VM to practise for the OSCP exam?",
    "Summarize section 4 of this policy for me.",
]
bad = []
for text in LEGIT:
    d = evaluate_input(text)
    if d.action.value in ("guardrails.block", "guardrails.escalate"):
        rules = [e.rule_id for ch in d.channels for e in ch.evidence]
        bad.append((text[:58], d.action.value, rules))
report("legit-allowlist", not bad,
       f"{len(LEGIT)-len(bad)}/{len(LEGIT)} allowed" if not bad else f"BLOCKED {bad}")

print()
print("=" * 78)
print("C. PII precision: formats that must redact vs must survive")
print("=" * 78)
MUST_REDACT = {
    "ssn-dash": "874-60-9123",
    "ssn-space": "874 60 9123",
    "ssn-dot": "874.60.9123",
    "ssn-underscore": "874_60_9123",
    "ssn-parens": "(874) 60-9123",
    "ssn-bare": "874609123",
    "card-spaces": "4539 9946 8712 5647",
    "card-dash": "4539-9946-8712-5647",
    "card-dots": "4539.9946.8712.5647",
    "card-16": "4539994687125647",
}
missed = []
for name, s in MUST_REDACT.items():
    out, ev = redact(f"value: {s}.")
    if s in out:
        missed.append(name)
report("pii-must-redact", not missed,
       "all redacted" if not missed else f"MISSED {missed}")

print()
print("D. PII precision: benign numeric strings that must NOT be mangled")
BENIGN_NUM = {
    # ZIP+4: nine digits + separator, but grouped 5-4 not 3-2-4 -> not an SSN.
    "zip": "ZIP 10012-3456",
    "phone-us": "Call me on 555-200-4100",
    "year-range": "from 1999-01-2000",
    "invoice-8": "Invoice 12345678",
    "iso-date": "2026-11-20",
    "qty": "qty 3.14159 units",
    "intl-phone": "+92 300 1234567",
    # DECIDED, not a bug: a bare 9-digit run is redacted even in
    # "Order 123456789" — see _ssn_context_ok. A missed SSN is a reportable
    # exposure; a redacted order number is visible and recoverable, so the
    # ambiguity resolves toward redaction (fail-closed). This probe asserts
    # the decision and its rationale so a future change is a conscious one.
    "order-id-9": "Order 123456789 shipped",
}
mangled = []
allowed_mangled = {"order-id-9"}
for name, s in BENIGN_NUM.items():
    ev = scan_pii(s)
    if any(e.rule_id in ("PII-SSN", "PII-CARD") for e in ev):
        if name in allowed_mangled:
            print(f"  NOTE  {name}: redacted by design (fail-closed bare form)")
        else:
            mangled.append((name, s, [e.rule_id for e in ev]))
report("pii-benign-numeric", not mangled,
       "no unintended false PII" if not mangled else f"FALSE POSITIVE {mangled}")

print()
print("=" * 78)
print(f"RESULT: {'CLEAN' if not fails else 'FAILURES: ' + str(fails)}")
print("=" * 78)
sys.exit(2 if fails else 0)
