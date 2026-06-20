import subprocess
import sys
from pathlib import Path


def test_verify_script_helpful_entrypoint_exists() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    script = repository_root / "scripts" / "verify.py"

    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(script)],
        cwd=repository_root,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
