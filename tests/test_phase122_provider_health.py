from __future__ import annotations

from ic_copilot.llm.providers.base_json import ProviderJSONError
from ic_copilot.provider_health import ProviderHealthProbe, check_product_provider_health
from ic_copilot.runtime_config import ProductRuntimeConfig


class HealthyClient:
    def generate_json(self, prompt_name, input_payload, response_model):
        return ProviderHealthProbe(ok=True, message="ok")


class AuthFailClient:
    def generate_json(self, prompt_name, input_payload, response_model):
        raise ProviderJSONError(
            "OpenAI HTTP error 401 invalid_api_key " + "sk-proj-" + "d" * 48,
            provider="openai",
        )


def test_provider_health_ok(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-" + "e" * 48)
    monkeypatch.setattr("ic_copilot.provider_health.create_product_llm_client", lambda config: HealthyClient())
    health = check_product_provider_health()
    assert health.status == "ok"
    assert health.fingerprint


def test_provider_health_auth_error_sanitized(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-" + "f" * 48)
    monkeypatch.setattr("ic_copilot.provider_health.create_product_llm_client", lambda config: AuthFailClient())
    health = check_product_provider_health()
    assert health.status == "auth_error"
    dumped = health.model_dump_json()
    assert "sk-proj" not in dumped
    assert "authentication failed" in health.safe_message.lower()


def test_provider_health_uses_product_config_api_key_env(tmp_path, monkeypatch) -> None:
    config_path = tmp_path / "product.yaml"
    config_path.write_text("llm:\n  provider: openai\n  api_key_env: PHASE122_PROVIDER_KEY\n")
    monkeypatch.setenv("PHASE122_PROVIDER_KEY", "sk-proj-" + "g" * 48)
    seen = {}

    def fake_client(config: ProductRuntimeConfig):
        seen["api_key_env"] = config.llm.api_key_env
        return HealthyClient()

    monkeypatch.setattr("ic_copilot.provider_health.create_product_llm_client", fake_client)
    assert check_product_provider_health(config_path).status == "ok"
    assert seen["api_key_env"] == "PHASE122_PROVIDER_KEY"
