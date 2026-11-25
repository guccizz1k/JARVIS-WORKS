"""Run the regression suite with the pinned overlay and isolated temp fixtures."""

import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    with TemporaryDirectory(prefix="jw-regression-") as scratch:
        env = {
            **{key: os.environ[key] for key in (
                "PATH", "PYTHONPATH", "LANG", "LC_ALL", "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
            ) if key in os.environ},
            "TMPDIR": scratch,
            "JARVIS_DB_PATH": str(Path(scratch) / "demo.sqlite3"),
        }
        subprocess.run(
            [sys.executable, "scripts/ci_rebuild_v79_overlay.py"],
            cwd=root, env=env, check=True,
        )
        return subprocess.call(
            [sys.executable, "-m", "pytest", "-q", "tests", "-ra", *sys.argv[1:]],
            cwd=root, env=env,
        )


if __name__ == "__main__":
    raise SystemExit(main())
