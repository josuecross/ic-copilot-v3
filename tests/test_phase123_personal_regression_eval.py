import subprocess
import sys


def test_personal_regression_eval_help_works() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/run_personal_regression_eval.py", "--help"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "--live" in result.stdout


def test_personal_regression_eval_default_requires_no_provider(tmp_path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/run_personal_regression_eval.py",
            "--output-json",
            str(tmp_path / "results.json"),
            "--output-md",
            str(tmp_path / "results.md"),
            "--fail-on-safety",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "p3_in11084" in (tmp_path / "results.json").read_text()

