"""Environment loading helpers for local developer entrypoints."""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


def load_local_env() -> None:
    """Load a project-root .env file without overriding shell-provided values."""
    repo_root = Path(__file__).resolve().parents[2]
    env_path = repo_root / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
