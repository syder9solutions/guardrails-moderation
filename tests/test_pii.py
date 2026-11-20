"""PII guard: detection, validation, redaction round-trips."""
from src.pii import _luhn_ok, _ssn_ok, redact, scan_pii


def test_redacts_email_card_ssn_phone():
    text = ("Email jane.doe@acme.com, card 4111 1111 1111 1111, "
            "SSN 123-45-6789, phone 555-123-4567.")
    out, ev = redact(text)
    assert "[EMAIL]" in out and "[CARD]" in out
    assert "[SSN]" in out and "[PHONE]" in out
    ids = {e.rule_id for e in ev}
    assert {"PII-EMAIL", "PII-CARD", "PII-SSN", "PII-PHONE"} <= ids
    assert "jane.doe@acme.com" not in out
    assert "123-45-6789" not in out


def test_luhn_rejects_invalid_card():
    assert not _luhn_ok("1111222233334445")


def test_ssn_invalid_areas_not_flagged():
    out, ev = redact("refs 666-54-3211 and 900-11-2222")
    assert "[SSN]" not in out and not ev


def test_api_keys_detected():
    out, ev = redact("key: sk-abcdef0123456789abcdef0123456789")
    assert "[APIKEY]" in out


def test_labeled_field_redacted():
    out, ev = redact("Name: Jonathan Roe\nAddress: 12 Main St")
    assert "Jonathan Roe" not in out
    assert any(e.rule_id == "PII-LABELED-FIELD" for e in ev)


def test_redaction_preserves_surrounding_text():
    out, _ = redact("call me at 555-123-4567 thanks")
    assert out == "call me at [PHONE] thanks"
