"""Cross-platform verification gate for LLM Guardian."""

from __future__ import annotations

import compileall
import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPOSITORY_ROOT / "src"
TESTS_DIR = REPOSITORY_ROOT / "tests"
PYPROJECT_PATH = REPOSITORY_ROOT / "pyproject.toml"


def print_step(message: str) -> None:
    print(f"\n==> {message}")


def run_subprocess(args: list[str]) -> None:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(SRC_DIR)
        if not existing_pythonpath
        else os.pathsep.join([str(SRC_DIR), existing_pythonpath])
    )
    subprocess.run(args, cwd=REPOSITORY_ROOT, env=env, check=True)


def validate_pyproject() -> None:
    print_step("Validating pyproject.toml")
    with PYPROJECT_PATH.open("rb") as file:
        tomllib.load(file)
    print("pyproject.toml is valid TOML.")


def compile_directory(path: Path) -> None:
    if not path.exists():
        print(f"Skipping compile: {path.name}/ does not exist.")
        return

    print_step(f"Compiling {path.name}/")
    ok = compileall.compile_dir(path, quiet=1)
    if not ok:
        raise SystemExit(f"Compilation failed for {path}")
    print(f"{path.name}/ compiled successfully.")


def run_pytest() -> None:
    if not TESTS_DIR.exists():
        print("Skipping pytest: tests/ does not exist.")
        return

    print_step("Running pytest")
    with tempfile.TemporaryDirectory(prefix="llm-guardian-pytest-") as temp_dir:
        # Use the OS temp root for tmp_path and disable pytest's cache provider so
        # verification does not depend on project-local .pytest_tmp/.pytest_cache writes on Windows.
        run_subprocess(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                f"--basetemp={temp_dir}",
            ]
        )


def validate_attack_library() -> None:
    print_step("Validating attack library")
    run_subprocess([sys.executable, "-m", "llm_guardian.cli", "validate-attacks"])


def main() -> int:
    try:
        validate_pyproject()
        compile_directory(SRC_DIR)
        compile_directory(TESTS_DIR)
        run_pytest()
        validate_attack_library()
    except subprocess.CalledProcessError as exc:
        print(f"Verification command failed with exit code {exc.returncode}: {exc.cmd}")
        return exc.returncode
    except Exception as exc:
        print(f"Verification failed: {exc}")
        return 1

    print_step("Verification complete")
    print("All verification checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
