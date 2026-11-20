"""Configuration: environment loading + backend selection.

Environment variables (all optional, sensible defaults for offline/stub use):
    GUARDRAILS_BACKEND   "stub" (default) | "live"
    OPENAI_BASE_URL      OpenAI-compatible endpoint for the live backend
    OPENAI_API_KEY       bearer token for the live backend
    MODEL_NAME           chat model id (default from project .env: omniroute)
    MAX_REQUEST_BYTES    request body cap for the API (default 65536)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def load_dotenv(path: Path | None = None) -> dict[str, str]:
    """Minimal .env loader (no third-party dep). Existing env vars win."""
    loaded: dict[str, str] = {}
    candidates = [path] if path else [
        Path(__file__).resolve().parent.parent / ".env",
        Path.cwd() / ".env",
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        for raw in candidate.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip("'\"")
            if key and key not in os.environ:
                os.environ[key] = value
                loaded[key] = value
        break
    return loaded


@dataclass(frozen=True)
class Settings:
    backend: str = "stub"
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    max_request_bytes: int = 65_536
    max_repair_attempts: int = 1  # bounded repair loop: initial try + 1 repair

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        return cls(
            backend=os.environ.get("GUARDRAILS_BACKEND", "stub").strip().lower(),
            base_url=os.environ.get("OPENAI_BASE_URL", "").strip(),
            api_key=os.environ.get("OPENAI_API_KEY", "").strip(),
            model=os.environ.get("MODEL_NAME", "stub-compliance").strip(),
            max_request_bytes=int(os.environ.get("MAX_REQUEST_BYTES", "65536")),
        )


SETTINGS = Settings.from_env()
