"""Guarded /chat proxy — the deployment surface (v3 architecture).

Every request flows through the same pipeline as the evals: input guard →
document fencing → backend → output guard with bounded repair → fail-closed.

Endpoints:
    GET  /health          liveness + backend mode
    GET  /policy          the enforcement policy (transparency for reviewers)
    POST /chat            guarded chat completion
    POST /redteam/probe   single adversarial probe + verdict (demo box)

Security posture of the API itself:
    * request body size cap (MAX_REQUEST_BYTES)
    * conservative field size caps; over-cap input is REDACTED-truncated,
      not silently processed
    * decisions are returned machine-readably so callers can audit
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import SETTINGS, load_dotenv  # noqa: E402
from src.exceptions import BackendUnavailable  # noqa: E402
from src.pipeline import (Action, make_backend, run_chat)  # noqa: E402
from src.policy import (INJECTION_THRESHOLD, JAILBREAK_THRESHOLD,  # noqa: E402
                        ESCALATION_THRESHOLD)
from src.tools import ToolDenied, build_default_registry, gated_dispatch  # noqa: E402

load_dotenv()  # idempotent: existing env wins; keeps direct `uvicorn app.main:app` working

app = FastAPI(title="guardrails-moderation proxy", version="1.0.0")

# Single shared backend instance (stub is stateless; live backend uses its
# own httpx client pool).
_BACKEND = make_backend(SETTINGS)

MAX_MESSAGE_CHARS = 20_000
MAX_DOC_CHARS = 60_000
MAX_DOCS = 8


def _policy_payload() -> dict:
    """Machine-readable enforcement policy for reviewers/auditors."""
    return {
        "enforcement_order": [
            "1. input guard on user message (moderation -> jailbreak -> "
            "injection -> PII redaction)",
            "2. untrusted documents scanned individually; weaponized docs "
            "dropped, survivors fenced as data-only",
            "3. backend call",
            "4. output guard (moderation -> jailbreak -> injection "
            "reflection -> PII redaction) with bounded repair loop",
            "5. fail closed on unresolved violations",
        ],
        "thresholds": {
            "injection_block": INJECTION_THRESHOLD,
            "jailbreak_block": JAILBREAK_THRESHOLD,
            "escalate": ESCALATION_THRESHOLD,
        },
        "fail_mode": "closed",
        "max_repair_attempts": SETTINGS.max_repair_attempts,
        "request_caps": {
            "max_request_bytes": SETTINGS.max_request_bytes,
            "max_message_chars": MAX_MESSAGE_CHARS,
            "max_doc_chars": MAX_DOC_CHARS,
            "max_documents": MAX_DOCS,
        },
        "tool_policy": {
            "least_privilege": "allowlist registry + allowed_arg_keys",
            "high_stakes": "human-in-the-loop approval gate",
        },
    }


class ChatRequest(BaseModel):
    message: str = Field(..., description="User turn.")
    documents: list[str] = Field(
        default_factory=list,
        description=("Untrusted document/retrieved content; scanned, "
                     "fenced, and never treated as instructions."))
    include_evidence: bool = Field(
        default=False,
        description="Include guard evidence (rule ids + excerpts) in response.")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "backend": _BACKEND.name,
        "thresholds": {
            "injection": INJECTION_THRESHOLD,
            "jailbreak": JAILBREAK_THRESHOLD,
            "escalate": ESCALATION_THRESHOLD,
        },
    }


@app.get("/policy")
def policy() -> dict:
    return _policy_payload()


@app.post("/chat")
def chat(req: ChatRequest, request: Request) -> JSONResponse:
    t0 = time.perf_counter()

    # ---- transport-level caps ----------------------------------------------
    declared = request.headers.get("content-length")
    if declared and declared.isdigit():
        if int(declared) > SETTINGS.max_request_bytes:
            return JSONResponse(status_code=413, content={
                "error": "payload too large",
                "limit_bytes": SETTINGS.max_request_bytes,
            })

    message = req.message[:MAX_MESSAGE_CHARS]
    docs = [d[:MAX_DOC_CHARS] for d in req.documents[:MAX_DOCS]]

    res = run_chat(message, documents=docs, backend=_BACKEND)
    body = res.to_dict()
    body["wall_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    if not req.include_evidence:
        body.pop("decision_in", None)
        body.pop("decision_out", None)
    status = 200 if res.action in (Action.ALLOW, Action.REDACT) else 422
    return JSONResponse(status_code=status, content=body)


@app.post("/redteam/probe")
def redteam_probe(req: ChatRequest) -> JSONResponse:
    """Single adversarial probe for the interactive demo box: returns the
    verdict, the reply the user would see, and which rules fired."""
    t0 = time.perf_counter()
    message = req.message[:MAX_MESSAGE_CHARS]
    docs = [d[:MAX_DOC_CHARS] for d in req.documents[:MAX_DOCS]]
    res = run_chat(message, documents=docs, backend=_BACKEND)
    body = res.to_dict()
    body["wall_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return JSONResponse(status_code=200, content=body)


@app.get("/demo", include_in_schema=False)
def demo_page() -> FileResponse:
    return FileResponse(PROJECT_ROOT / "app" / "static" / "index.html")


@app.get("/evals/redteam_report.json", include_in_schema=False)
def eval_report():
    path = PROJECT_ROOT / "evals" / "redteam_report.json"
    if not path.is_file():
        return JSONResponse(status_code=404, content={
            "error": "report not generated yet — run: python -m redteam.eval --stub"})
    return FileResponse(path)


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {
        "service": "guardrails-moderation proxy",
        "endpoints": ["/health", "/policy", "/chat", "/chat/unguarded",
                      "/redteam/probe", "/tools/dispatch", "/demo"],
    }


# ---- v0 baseline: raw backend, zero protections ---------------------------
# Lets a reviewer hit the SAME backend with and without guards and watch the
# difference live (this is what the before/after ASR table measures).

@app.post("/chat/unguarded")
def chat_unguarded(req: ChatRequest) -> JSONResponse:
    message = req.message[:MAX_MESSAGE_CHARS]
    docs = [d[:MAX_DOC_CHARS] for d in req.documents[:MAX_DOCS]]
    messages = [
        {"role": "system", "content": "You are a customer-support assistant."},
        {"role": "user", "content": message},
        *[{"role": "user", "content": d} for d in docs],
    ]
    t0 = time.perf_counter()
    try:
        reply = _BACKEND.complete(messages)
    except BackendUnavailable as exc:
        return JSONResponse(status_code=502, content={
            "error": "backend_unavailable", "detail": str(exc)})
    return JSONResponse(content={
        "reply": reply,
        "guardrails": "none",
        "wall_ms": round((time.perf_counter() - t0) * 1000, 2),
    })


# ---- least-privilege tool execution (v3) ------------------------------------
# High-stakes tools return pending_human_approval unless approved=true; the
# capability fence (allowlist + arg allowlist + hard caps) always applies.

class ToolCallRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    args: dict = Field(default_factory=dict)
    approved: bool = False


_REGISTRY = build_default_registry()


@app.post("/tools/dispatch")
def tools_dispatch(req: ToolCallRequest) -> JSONResponse:
    try:
        out = gated_dispatch(_REGISTRY, req.name, req.args,
                             approved=req.approved)
    except ToolDenied:
        return JSONResponse(status_code=403, content={
            "error": "tool_denied",
            "detail": "rejected by the least-privilege tool fence",
        })
    return JSONResponse(content=out)
