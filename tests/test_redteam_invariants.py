"""Red-team invariants: the whole corpus must stay defended; benign
holdout must not over-block. This is the CI gate for the eval table."""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from redteam.corpus import ATTACKS, BENIGN, validate_canaries  # noqa: E402
from redteam.harness import run_attack, run_benign  # noqa: E402
from src.pipeline import (SemanticLLMBackend, StubLLMBackend,  # noqa: E402
                            run_chat)


@pytest.fixture(scope="module")
def backend():
    return StubLLMBackend()


def _pipeline(message, documents=None):
    return run_chat(message, documents=documents, backend=StubLLMBackend())


def test_corpus_canaries_detectable():
    validate_canaries()


@pytest.mark.parametrize("case", ATTACKS, ids=[c.id for c in ATTACKS])
def test_attack_defended(case, backend):
    res = run_attack(case, "guarded", StubLLMBackend(), _pipeline)
    assert not res.success, (
        f"{case.id} ({case.category}): attack succeeded through guardrails. "
        f"reply={res.reply_excerpt!r}")


@pytest.mark.parametrize("case", BENIGN, ids=[c.id for c in BENIGN])
def test_benign_not_overblocked(case, backend):
    _, rg = run_benign(case, StubLLMBackend(), _pipeline)
    assert not rg.success, (
        f"{case.id}: legitimate input over-blocked "
        f"(action={rg.action}, rules={rg.evidence_rules})")


# --- same corpus, honest baseline -------------------------------------------
# Running the gates ONLY against StubLLMBackend was QA defect D4: the stub
# shares its compliance predicate with the guard, so the gates pass even with
# detection disabled. These twins run the identical assertions against the
# intent-compliant baseline, where the guard has to do the work itself.

def _pipeline_semantic(message, documents=None):
    return run_chat(message, documents=documents,
                    backend=SemanticLLMBackend())


@pytest.mark.parametrize("case", ATTACKS, ids=[c.id for c in ATTACKS])
def test_attack_defended_semantic(case):
    res = run_attack(case, "guarded", SemanticLLMBackend(), _pipeline_semantic)
    assert not res.success, (
        f"{case.id} ({case.category}): attack succeeded against the honest "
        f"baseline. reply={res.reply_excerpt!r} action={res.action}")


@pytest.mark.parametrize("case", BENIGN, ids=[c.id for c in BENIGN])
def test_benign_not_overblocked_semantic(case):
    _, rg = run_benign(case, SemanticLLMBackend(), _pipeline_semantic)
    assert not rg.success, (
        f"{case.id}: legitimate input over-blocked against the honest "
        f"baseline (action={rg.action}, rules={rg.evidence_rules})")
