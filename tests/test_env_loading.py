from __future__ import annotations

import os

from ic_copilot.env import load_dotenv_if_present


def test_dotenv_loads_openai_key_when_absent(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    path = tmp_path / ".env"
    path.write_text("\n# local secrets\nOPENAI_API_KEY='sk-test-secret'\n")
    assert load_dotenv_if_present(path) is True
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert "OPENAI_API_KEY" in os.environ


def test_dotenv_does_not_overwrite_existing_value(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "existing")
    path = tmp_path / ".env"
    path.write_text("OPENAI_API_KEY=new\n")
    assert load_dotenv_if_present(path) is True
    assert os.environ["OPENAI_API_KEY"] == "existing"


def test_dotenv_ignores_comments_blank_lines_and_absent_file(tmp_path, monkeypatch):
    monkeypatch.delenv("EXAMPLE_KEY", raising=False)
    path = tmp_path / ".env"
    path.write_text("\n# comment\n\nexport EXAMPLE_KEY=\"value\"\n")
    assert load_dotenv_if_present(path) is True
    assert os.environ["EXAMPLE_KEY"] == "value"
    assert load_dotenv_if_present(tmp_path / "missing.env") is False
