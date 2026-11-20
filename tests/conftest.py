"""Test fixtures: stub backend, corpus access, run_chat wrapper."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline import PipelineResult, StubLLMBackend, run_chat  # noqa: E402


@pytest.fixture()
def backend():
    return StubLLMBackend()


@pytest.fixture()
def guarded(backend):
    def _run(message: str, documents: list[str] | None = None) -> PipelineResult:
        return run_chat(message, documents=documents, backend=backend)
    return _run
