from __future__ import annotations

from pathlib import Path


def test_private_and_secret_paths_are_gitignored():
    entries = {
        line.strip()
        for line in Path(".gitignore").read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    assert ".env" in entries
    assert ".ic_copilot/" in entries
    assert "data/private/" in entries
    assert "local_corpus/" in entries
