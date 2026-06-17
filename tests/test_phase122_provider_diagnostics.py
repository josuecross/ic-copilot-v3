from __future__ import annotations

from ic_copilot.runtime_diagnostics import collect_provider_runtime_diagnostics, fingerprint_secret


def test_fingerprint_secret_does_not_expose_raw_secret() -> None:
    secret = "sk-proj-" + "a" * 48
    fingerprint = fingerprint_secret(secret)
    assert len(fingerprint) == 12
    assert secret not in fingerprint
    assert "sk-" not in fingerprint


def test_diagnostics_reports_fingerprint_only(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    secret = "sk-proj-" + "b" * 48
    (tmp_path / ".env").write_text(f"PHASE122_KEY={secret}\n")
    (tmp_path / "ic_copilot.local.yaml").write_text(
        "llm:\n  provider: openai\n  model: gpt-4.1-mini\n  api_key_env: PHASE122_KEY\n"
    )
    monkeypatch.delenv("PHASE122_KEY", raising=False)
    diag = collect_provider_runtime_diagnostics()
    dumped = diag.model_dump_json()
    assert diag.api_key_env == "PHASE122_KEY"
    assert diag.credential.present is True
    assert diag.credential.fingerprint
    assert secret not in dumped
    assert diag.config_path_used == "ic_copilot.local.yaml"
    assert any("not OPENAI_API_KEY" in warning for warning in diag.warnings)


def test_diagnostics_detects_missing_key(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ic_copilot.local.yaml").write_text(
        "llm:\n  provider: openai\n  model: gpt-4.1-mini\n  api_key_env: PHASE122_MISSING\n"
    )
    monkeypatch.delenv("PHASE122_MISSING", raising=False)
    diag = collect_provider_runtime_diagnostics()
    assert diag.credential.present is False
    assert "PHASE122_MISSING is not configured." in diag.errors
