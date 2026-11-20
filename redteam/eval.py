#!/usr/bin/env python3
"""Run the red-team suite and write evals/redteam_report.json.

Usage:
    python -m redteam.eval --stub          # deterministic simulated-vulnerable model
    python -m redteam.eval --live          # real backend (OPENAI_BASE_URL + key)
    python -m redteam.eval --live --label "openai-gpt-4o-mini"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam.corpus import corpus_stats, validate_canaries
from redteam.harness import run_suite, write_report
from src.pipeline import (LiveLLMBackend, SemanticLLMBackend, StubLLMBackend,
                          run_chat)
from src.config import SETTINGS


def main() -> int:
    ap = argparse.ArgumentParser(description="guardrails red-team eval")
    ap.add_argument("--stub", action="store_true",
                    help="use the deterministic simulated-vulnerable stub")
    ap.add_argument("--semantic", action="store_true",
                    help="use the intent-compliant backend (the honest "
                         "vulnerable baseline; required for a falsifiable ASR)")
    ap.add_argument("--live", action="store_true",
                    help="use the live OpenAI-compatible backend")
    ap.add_argument("--label", default="guardrails-v1")
    ap.add_argument("--out", default=None,
                    help="output path (default evals/redteam_report.json)")
    args = ap.parse_args()

    validate_canaries()

    if args.live:
        backend = LiveLLMBackend(
            SETTINGS.base_url, SETTINGS.api_key, SETTINGS.model)
    elif args.semantic:
        backend = SemanticLLMBackend()
    else:
        backend = StubLLMBackend()

    def pipeline_fn(message: str, documents: list[str] | None = None):
        return run_chat(message, documents=documents, backend=backend)

    print(f"corpus: {corpus_stats()}", file=sys.stderr)
    report = run_suite(backend, pipeline_fn, label=args.label)

    out_path = args.out or str(Path(__file__).resolve().parent.parent
                               / "evals" / "redteam_report.json")
    write_report(report, out_path)

    c = report["comparison"]
    print(json.dumps({
        "overall": c["overall"],
        "by_category": c["by_category"],
        "false_positive_rate": c["false_positive_rate"],
        "latency_ms": c["latency_ms"],
        "residual_attack_cases": c["residual_attack_cases"],
        "report": out_path,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
