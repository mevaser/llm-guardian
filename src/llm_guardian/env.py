"""Environment loading helpers for local developer entrypoints."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


def load_local_env(env_path: Path | None = None) -> bool:
    """Load a project-root .env file without overriding shell-provided values."""
    if os.environ.get("LLM_GUARDIAN_DISABLE_DOTENV") == "1":
        return False
    if env_path is None:
        repo_root = Path(__file__).resolve().parents[2]
        env_path = repo_root / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=False)
        return True
    return False
