"""Environment loading helpers for local developer entrypoints."""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


def load_local_dotenv() -> None:
    """Load a project-root .env file without overriding shell-provided values."""

    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
