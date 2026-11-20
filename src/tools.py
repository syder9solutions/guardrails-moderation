"""Least-privilege tool registry with human-in-the-loop gating.

Defense-in-depth: even if injection hijacks the model's *intent*, the tool
layer is the last line that decides what the agent can *do*. Each tool
declares its risk tier; high-stakes tools require explicit human approval.
This is the OWASP LLM06 (sensitive information disclosure) / ASI09
(human-agent trust) mitigation — capability fencing, not prompt hope.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .exceptions import GuardrailError


class ToolDenied(GuardrailError):
    """A tool call violated its capability fence."""


@dataclass(frozen=True)
class RiskPolicy:
    tier: str                 # "low" | "high"
    requires_hitl: bool       # human-in-the-loop approval needed
    allowed_arg_keys: frozenset[str]
    max_arg_bytes: int = 2048


@dataclass
class Tool:
    name: str
    description: str
    policy: RiskPolicy
    fn: Callable[..., Any]

    def run(self, args: dict[str, Any], approved: bool = False) -> Any:
        if self.policy.tier == "high" and not approved:
            raise ToolDenied(
                f"tool '{self.name}' is high-stakes and requires explicit "
                "human approval (HITL) before execution"
            )
        unexpected = set(args) - self.policy.allowed_arg_keys
        if unexpected:
            raise ToolDenied(
                f"tool '{self.name}' rejected unexpected arguments: "
                f"{sorted(unexpected)} — parameter injection blocked"
            )
        blob = repr(args)
        if len(blob) > self.policy.max_arg_bytes:
            raise ToolDenied(
                f"tool '{self.name}' argument payload too large "
                f"({len(blob)} > {self.policy.max_arg_bytes})"
            )
        return self.fn(**args)


# ---- concrete least-privilege tools ---------------------------------------

def _read_public_doc(doc_id: str) -> dict[str, Any]:
    """Read-only lookup over a fixed allowlist — no filesystem access."""
    allowlist = {
        "faq-shipping": "Orders ship within 2 business days.",
        "faq-returns": "Returns accepted within 30 days, unused.",
        "faq-warranty": "Warranty covers manufacturing defects for 12 months.",
    }
    if doc_id not in allowlist:
        raise ToolDenied(f"unknown doc_id '{doc_id}' — allowlist enforced")
    return {"doc_id": doc_id, "text": allowlist[doc_id]}


def _submit_ticket(summary: str, priority: str = "normal") -> dict[str, Any]:
    """High-stakes: creates a real support ticket — needs HITL."""
    return {"ticket_id": "TCK-0001", "summary": summary[:200],
            "priority": priority}


def _issue_refund(amount_cents: int, order_id: str) -> dict[str, Any]:
    """High-stakes: moves money — needs HITL and hard amount cap."""
    if amount_cents > 5000:
        raise ToolDenied(
            f"refund {amount_cents} cents exceeds hard cap 5000 — "
            "escalate to a human finance operator"
        )
    return {"refunded": amount_cents, "order_id": order_id,
            "status": "requires_human_settlement"}


def build_default_registry() -> dict[str, Tool]:
    registry: dict[str, Tool] = {
        "read_public_doc": Tool(
            name="read_public_doc",
            description="Read one FAQ document by allowlisted id.",
            policy=RiskPolicy(
                tier="low", requires_hitl=False,
                allowed_arg_keys=frozenset({"doc_id"}),
            ),
            fn=_read_public_doc,
        ),
        "submit_ticket": Tool(
            name="submit_ticket",
            description="Create a support ticket. Requires human approval.",
            policy=RiskPolicy(
                tier="high", requires_hitl=True,
                allowed_arg_keys=frozenset({"summary", "priority"}),
            ),
            fn=_submit_ticket,
        ),
        "issue_refund": Tool(
            name="issue_refund",
            description="Issue a refund. Requires human approval; capped.",
            policy=RiskPolicy(
                tier="high", requires_hitl=True,
                allowed_arg_keys=frozenset({"amount_cents", "order_id"}),
            ),
            fn=_issue_refund,
        ),
    }
    return registry


def gated_dispatch(
    registry: dict[str, Tool],
    name: str,
    args: dict[str, Any],
    *,
    approved: bool = False,
) -> dict[str, Any]:
    """The only entry point the agent loop may use to execute tools."""
    if name not in registry:
        raise ToolDenied(
            f"tool '{name}' not in registry — capability fence holds"
        )
    tool = registry[name]
    if tool.policy.requires_hitl and not approved:
        return {
            "status": "pending_human_approval",
            "tool": name,
            "args_redacted": {k: "***" for k in args},
        }
    result = tool.run(args, approved=approved)
    return {"status": "executed", "tool": name, "result": result}
