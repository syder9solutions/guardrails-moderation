"""Tool fence: least privilege, HITL, parameter injection."""
import pytest

from src.tools import build_default_registry, gated_dispatch


def test_high_stakes_requires_approval():
    reg = build_default_registry()
    out = gated_dispatch(reg, "issue_refund",
                         {"amount_cents": 150_000, "order_id": "A-1"})
    assert out["status"] == "pending_human_approval"
    # arguments must be redacted in the approval payload
    assert set(out["args_redacted"].values()) == {"***"}


def test_approved_high_stakes_executes():
    reg = build_default_registry()
    out = gated_dispatch(reg, "issue_refund",
                         {"amount_cents": 4_500, "order_id": "A-1"},
                         approved=True)
    assert out["status"] == "executed"
    assert out["result"]["refunded"] == 4_500


def test_read_only_tool_runs_without_approval():
    reg = build_default_registry()
    out = gated_dispatch(reg, "read_public_doc",
                         {"doc_id": "faq-shipping"})
    assert out["status"] == "executed"


def test_path_traversal_in_doc_id_blocked():
    reg = build_default_registry()
    with pytest.raises(Exception):
        gated_dispatch(reg, "read_public_doc",
                       {"doc_id": "../../../etc/passwd"})


def test_extra_injection_params_rejected():
    reg = build_default_registry()
    with pytest.raises(Exception):
        gated_dispatch(reg, "read_public_doc",
                       {"doc_id": "faq-shipping", "path": "/etc/passwd"})


def test_unknown_tool_denied():
    reg = build_default_registry()
    with pytest.raises(Exception):
        gated_dispatch(reg, "delete_all_users", {})


def test_refund_cap_enforced():
    reg = build_default_registry()
    with pytest.raises(Exception):
        gated_dispatch(reg, "issue_refund",
                       {"amount_cents": 10_000_000, "order_id": "A-1"},
                       approved=True)
