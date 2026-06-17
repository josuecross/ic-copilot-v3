from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field

from ic_copilot.env import maybe_load_local_env, parse_dotenv_values
from ic_copilot.runtime_config import ProductRuntimeConfig, default_config_paths, product_provider_is_configured
from ic_copilot.schemas import StrictBaseModel


class CredentialPresence(StrictBaseModel):
    env_var: str
    present: bool
    source_hint: str | None = None
    fingerprint: str | None = None
    length: int | None = None
    looks_like_openai_project_key: bool | None = None
    warnings: list[str] = Field(default_factory=list)


class ProviderRuntimeDiagnostics(StrictBaseModel):
    provider: str
    model: str
    api_key_env: str
    credential: CredentialPresence
    config_path_used: str | None = None
    env_files_loaded: list[str] = Field(default_factory=list)
    shell_env_present: bool = False
    local_env_present: bool = False
    effective_key_fingerprint: str | None = None
    base_url: str | None = None
    timeout_seconds: float
    product_runtime_ready: bool
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def fingerprint_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _find_config_path(path: str | Path | None) -> Path | None:
    if path is not None:
        return Path(path)
    for candidate in default_config_paths():
        if candidate.exists():
            return candidate
    return None


def _load_config_and_path(path: str | Path | None = None) -> tuple[ProductRuntimeConfig, Path | None]:
    config_path = _find_config_path(path)
    if config_path is not None:
        data = yaml.safe_load(config_path.read_text()) or {}
        return ProductRuntimeConfig.model_validate(data), config_path
    return ProductRuntimeConfig(), None


def _likely_env_files() -> list[Path]:
    paths = [Path.cwd() / ".env"]
    parent = Path.cwd().parent / ".env"
    if parent not in paths:
        paths.append(parent)
    return [path for path in paths if path.exists()]


def collect_provider_runtime_diagnostics(config_path: str | Path | None = None) -> ProviderRuntimeDiagnostics:
    loaded = maybe_load_local_env()
    config, used_path = _load_config_and_path(config_path)
    env_var = config.llm.api_key_env
    effective = os.environ.get(env_var)
    env_values = {
        path: parse_dotenv_values(path)
        for path in _likely_env_files()
    }
    local_value = None
    local_path = None
    for path, values in env_values.items():
        if env_var in values:
            local_value = values[env_var]
            local_path = path
            break
    shell_env_present = bool(effective) and not any(
        item.name == env_var and item.action == "set_from_dotenv" for item in loaded.variables
    )
    local_env_present = local_value is not None
    warnings: list[str] = []
    errors: list[str] = []
    credential_warnings: list[str] = []
    if len(_likely_env_files()) > 1:
        warnings.append("Multiple .env files exist near the app; only the current working directory .env is auto-loaded.")
    if used_path is None and any(candidate.exists() for candidate in default_config_paths()):
        warnings.append("Product config path resolution was ambiguous.")
    explicit_config_candidates = [path for path in default_config_paths() if path.exists()]
    if config_path is None and len(explicit_config_candidates) > 1:
        warnings.append("Multiple product config candidates exist; IC_COPILOT_CONFIG takes precedence.")
    if env_var != "OPENAI_API_KEY" and config.llm.provider == "openai":
        warnings.append(f"OpenAI product config uses {env_var}, not OPENAI_API_KEY.")
    if config.llm.model != ProductRuntimeConfig().llm.model:
        warnings.append("Configured model differs from the example default.")
    if effective and local_value and effective != local_value:
        credential_warnings.append(
            f"{env_var} exists in both process environment and {local_path}; the effective value differs."
        )
    if not effective and config.llm.provider != "local_http":
        errors.append(f"{env_var} is not configured.")

    source_hint = None
    if effective:
        if any(item.name == env_var and item.action == "set_from_dotenv" for item in loaded.variables):
            source_hint = f".env:{loaded.path}"
        elif local_value and effective == local_value:
            source_hint = f"process environment or previously loaded .env:{local_path}"
        else:
            source_hint = "process environment"

    credential = CredentialPresence(
        env_var=env_var,
        present=bool(effective) if config.llm.provider != "local_http" else bool(config.llm.base_url),
        source_hint=source_hint,
        fingerprint=fingerprint_secret(effective) if effective else None,
        length=len(effective) if effective else None,
        looks_like_openai_project_key=effective.startswith("sk-proj-") if effective and config.llm.provider == "openai" else None,
        warnings=credential_warnings,
    )
    return ProviderRuntimeDiagnostics(
        provider=config.llm.provider,
        model=config.llm.model,
        api_key_env=env_var,
        credential=credential,
        config_path_used=str(used_path) if used_path else None,
        env_files_loaded=[loaded.path] if loaded.loaded else [],
        shell_env_present=shell_env_present,
        local_env_present=local_env_present,
        effective_key_fingerprint=credential.fingerprint,
        base_url=config.llm.base_url,
        timeout_seconds=config.llm.timeout_seconds,
        product_runtime_ready=product_provider_is_configured(config),
        warnings=warnings + credential_warnings,
        errors=errors,
    )


def format_provider_diagnostics_for_ui(diag: ProviderRuntimeDiagnostics) -> dict[str, Any]:
    return diag.model_dump(mode="json")


def format_provider_diagnostics_markdown(diag: ProviderRuntimeDiagnostics) -> str:
    lines = [
        "# Product Provider Diagnostics",
        "",
        f"- provider: {diag.provider}",
        f"- model: {diag.model}",
        f"- api_key_env: {diag.api_key_env}",
        f"- credential_present: {diag.credential.present}",
        f"- credential_fingerprint: {diag.effective_key_fingerprint or 'n/a'}",
        f"- credential_length: {diag.credential.length or 'n/a'}",
        f"- config_path_used: {diag.config_path_used or 'built-in defaults'}",
        f"- env_files_loaded: {', '.join(diag.env_files_loaded) if diag.env_files_loaded else 'none'}",
        f"- shell_env_present: {diag.shell_env_present}",
        f"- local_env_present: {diag.local_env_present}",
        f"- product_runtime_ready: {diag.product_runtime_ready}",
        "",
        "## Warnings",
    ]
    lines.extend(f"- {warning}" for warning in diag.warnings) if diag.warnings else lines.append("- none")
    lines.append("")
    lines.append("## Errors")
    lines.extend(f"- {error}" for error in diag.errors) if diag.errors else lines.append("- none")
    return "\n".join(lines) + "\n"
