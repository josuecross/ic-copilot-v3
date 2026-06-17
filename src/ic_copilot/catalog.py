from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

import yaml

from ic_copilot.schemas import CommandRegistryEntry, EntityType, ServiceCatalogEntry


def _norm(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _adapt_catalog_entry(raw: dict) -> dict:
    entry = dict(raw)
    ownership = dict(entry.get("ownership") or {})
    if entry.get("owning_team"):
        ownership.setdefault("owning_team", entry.pop("owning_team"))
    if entry.get("support_team"):
        ownership.setdefault("support_team", entry.pop("support_team"))
    entry["ownership"] = ownership

    slack = dict(entry.get("slack") or {})
    if entry.get("slack_targets") is not None:
        slack.setdefault("targets", entry.pop("slack_targets"))
    entry["slack"] = slack

    oncall = dict(entry.get("oncall") or {})
    if "oncall_lookup_command" in entry:
        command = entry.pop("oncall_lookup_command")
        if command:
            oncall.setdefault("lookup_command", command)
    entry["oncall"] = oncall

    entry.setdefault("kind", "service")
    entry.setdefault("aliases", [])
    entry.setdefault("known_commands", [])
    if oncall.get("lookup_command") and not entry["known_commands"]:
        entry["known_commands"] = [
            {
                "type": "oncall",
                "command": oncall["lookup_command"],
                "requires_human_approval": True,
                "allowed_prefixes": ["@zsrebot oncall"],
            }
        ]
    entry["runbooks"] = _as_list(entry.get("runbooks"))
    entry["dashboards"] = _as_list(entry.get("dashboards"))
    return entry


def load_service_catalog(path: str | Path) -> list[ServiceCatalogEntry]:
    data = yaml.safe_load(Path(path).read_text()) or []
    entries = data.get("services", data) if isinstance(data, dict) else data
    return [ServiceCatalogEntry.model_validate(_adapt_catalog_entry(entry)) for entry in entries]


def _names(entry: ServiceCatalogEntry) -> set[str]:
    return {_norm(entry.service_id), _norm(entry.canonical_name), *{_norm(alias) for alias in entry.aliases}}


def resolve_service_or_team(
    name_or_alias: str,
    catalog: Iterable[ServiceCatalogEntry],
) -> list[ServiceCatalogEntry]:
    query = _norm(name_or_alias)
    if not query:
        return []
    exact: list[ServiceCatalogEntry] = []
    fuzzy: list[ServiceCatalogEntry] = []
    for entry in catalog:
        names = _names(entry)
        if query in names:
            exact.append(entry)
        elif any(query in name or name in query for name in names if len(name) >= 3):
            fuzzy.append(entry)
    return exact + [entry for entry in fuzzy if entry not in exact]


def get_oncall_command_for_target(
    target: str,
    catalog: Iterable[ServiceCatalogEntry],
    command_registry: Iterable[CommandRegistryEntry] | None = None,
) -> str | None:
    registry_commands = {_norm(entry.command) for entry in command_registry or [] if entry.exact}
    for entry in resolve_service_or_team(target, catalog):
        for command in entry.known_commands:
            if command.get("type") == "oncall" and command.get("command"):
                normalized = " ".join(str(command["command"]).split())
                if not registry_commands or _norm(normalized) in registry_commands:
                    return normalized
        command = entry.oncall.get("lookup_command")
        if command:
            normalized = " ".join(str(command).split())
            if not registry_commands or _norm(normalized) in registry_commands:
                return normalized
    return None


def get_known_signals(service_id: str, catalog: Iterable[ServiceCatalogEntry]) -> list[str]:
    for entry in catalog:
        if _norm(entry.service_id) == _norm(service_id) or _norm(entry.canonical_name) == _norm(service_id):
            return entry.known_signals
    return []


def get_runbooks_and_dashboards(service_id: str, catalog: Iterable[ServiceCatalogEntry]) -> dict[str, list[str]]:
    for entry in catalog:
        if _norm(entry.service_id) == _norm(service_id) or _norm(entry.canonical_name) == _norm(service_id):
            return {"runbooks": entry.runbooks, "dashboards": entry.dashboards}
    return {"runbooks": [], "dashboards": []}


def build_command_registry(catalog: Iterable[ServiceCatalogEntry]) -> list[CommandRegistryEntry]:
    registry: list[CommandRegistryEntry] = []
    for entry in catalog:
        for command in entry.known_commands:
            if not command.get("command"):
                continue
            registry.append(
                CommandRegistryEntry(
                    command=command["command"],
                    target=entry.canonical_name,
                    source_service_id=entry.service_id,
                    requires_human_approval=bool(command.get("requires_human_approval", True)),
                    allowed_prefixes=command.get("allowed_prefixes", []),
                )
            )
        if entry.oncall.get("lookup_command"):
            registry.append(
                CommandRegistryEntry(
                    command=entry.oncall["lookup_command"],
                    target=entry.canonical_name,
                    source_service_id=entry.service_id,
                    requires_human_approval=True,
                    allowed_prefixes=["@zsrebot oncall"],
                )
            )
    by_command: dict[str, CommandRegistryEntry] = {}
    for entry in registry:
        by_command[_norm(entry.command)] = entry
    return list(by_command.values())


def load_command_registry(
    path: str | Path,
    catalog: Iterable[ServiceCatalogEntry] | None = None,
) -> list[CommandRegistryEntry]:
    """Load optional command registry and combine with catalog-derived exact commands.

    Contract registries may define patterns such as ``^@zsrebot oncall (.+)$``. The verifier
    still validates exact suggested commands, so catalog-derived lookup commands are added when
    a catalog is provided.
    """
    entries: list[CommandRegistryEntry] = []
    data = yaml.safe_load(Path(path).read_text()) or {}
    for raw in data.get("commands", data if isinstance(data, list) else []):
        pattern = raw.get("pattern")
        command = (
            raw.get("command")
            or raw.get("command_text")
            or raw.get("command_text_template")
            or pattern
            or raw.get("command_id", "")
        )
        entries.append(
            CommandRegistryEntry(
                command=command,
                target=raw.get("target", "*"),
                source_service_id=raw.get("source_service_id", raw.get("command_id", "registry")),
                requires_human_approval=bool(raw.get("requires_human_approval", True)),
                allowed_prefixes=raw.get("allowed_prefixes", []),
                command_id=raw.get("command_id"),
                command_type=raw.get("command_type", "pattern" if pattern else "exact"),
                pattern=pattern,
                requires_catalog_target=bool(raw.get("requires_catalog_target", False)),
                danger_level=raw.get("danger_level", "read_only_lookup"),
                exact=pattern is None,
            )
        )
    if catalog is not None:
        entries.extend(build_command_registry(catalog))
    by_key: dict[str, CommandRegistryEntry] = {}
    for entry in entries:
        by_key[f"{entry.command_type}:{_norm(entry.command)}:{_norm(entry.target)}"] = entry
    return list(by_key.values())


def catalog_entity_names(catalog: Iterable[ServiceCatalogEntry]) -> set[str]:
    names: set[str] = set()
    for entry in catalog:
        names.update(_names(entry))
    return names


def as_catalog_entity(entry: ServiceCatalogEntry):
    from ic_copilot.schemas import EntityRef

    return EntityRef(
        entity_type=entry.kind if isinstance(entry.kind, EntityType) else EntityType(entry.kind),
        display_name=entry.canonical_name,
        canonical_id=entry.service_id,
        source="catalog",
        confidence=1.0,
    )
