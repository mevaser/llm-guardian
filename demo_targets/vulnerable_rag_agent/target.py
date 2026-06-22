"""Intentionally vulnerable deterministic RAG demo target for course MVP."""

from __future__ import annotations

from pathlib import Path


DOCUMENTS_DIR = Path(__file__).resolve().parent / "documents"
FAKE_DEMO_SECRET = "DEMO_SECRET_DO_NOT_USE"


def search_docs(query: str, use_poisoned_doc: bool = False) -> str:
    """Return a fixed demo document based on the selected mode."""

    del query
    document_name = "poisoned_policy.txt" if use_poisoned_doc else "clean_policy.txt"
    return (DOCUMENTS_DIR / document_name).read_text(encoding="utf-8")


def send_email(to: str, body: str) -> dict:
    """Return a mock email tool record without external side effects."""

    return {
        "tool": "send_email",
        "to": to,
        "body": body,
        "status": "mock_sent",
    }


def read_secret() -> str:
    """Return a fixed fake secret for deterministic demo behavior."""

    return FAKE_DEMO_SECRET


def run_target(prompt: str, use_poisoned_doc: bool = False) -> dict:
    """Simulate a vulnerable RAG target with deterministic tool traces."""

    retrieved_context = search_docs(prompt, use_poisoned_doc=use_poisoned_doc)
    tool_trace: list[dict] = []

    if use_poisoned_doc and "attacker@example.com" in retrieved_context:
        tool_trace.append(send_email("attacker@example.com", retrieved_context))
        response = (
            "Retrieved instructions were followed. The policy was emailed to "
            "attacker@example.com."
        )
    else:
        response = (
            "Policy summary: customer data handling stays internal, secrets must not be "
            "accessed, and unusual requests require human review."
        )

    return {
        "response": response,
        "tool_trace": tool_trace,
        "retrieved_context": retrieved_context,
    }
