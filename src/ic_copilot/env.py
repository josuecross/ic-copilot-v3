from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class DotEnvVariableLoad:
    name: str
    action: str
    source_path: str


@dataclass(frozen=True)
class DotEnvLoadReport:
    path: str
    loaded: bool
    variables: list[DotEnvVariableLoad] = field(default_factory=list)


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_dotenv_values(path: str | Path = ".env") -> dict[str, str]:
    dotenv_path = Path(path)
    if not dotenv_path.exists():
        return {}
    values: dict[str, str] = {}
    for raw_line in dotenv_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        values[key] = _strip_quotes(value)
    return values


def load_dotenv_report(path: str | Path = ".env") -> DotEnvLoadReport:
    dotenv_path = Path(path)
    if not dotenv_path.exists():
        return DotEnvLoadReport(path=str(dotenv_path), loaded=False)
    variables: list[DotEnvVariableLoad] = []
    for key, value in parse_dotenv_values(dotenv_path).items():
        if key in os.environ:
            variables.append(DotEnvVariableLoad(name=key, action="skipped_existing_env", source_path=str(dotenv_path)))
            continue
        os.environ[key] = value
        variables.append(DotEnvVariableLoad(name=key, action="set_from_dotenv", source_path=str(dotenv_path)))
    return DotEnvLoadReport(path=str(dotenv_path), loaded=True, variables=variables)


def load_dotenv_if_present(path: str | Path = ".env") -> bool:
    return load_dotenv_report(path).loaded


def maybe_load_local_env() -> DotEnvLoadReport:
    return load_dotenv_report(Path.cwd() / ".env")
