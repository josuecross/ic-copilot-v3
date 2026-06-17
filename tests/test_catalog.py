from pathlib import Path
import tempfile

from ic_copilot.catalog import (
    get_oncall_command_for_target,
    load_command_registry,
    load_service_catalog,
    resolve_service_or_team,
)


CATALOG = Path("data/sample/service_catalog.yaml")


def test_resolves_revpro_aliases_to_revpro_and_support():
    catalog = load_service_catalog(CATALOG)
    names = {entry.canonical_name for entry in resolve_service_or_team("RevPro", catalog)}
    assert "RevPro" in names
    assert "RevPro Support" in names


def test_produces_revpro_support_oncall_command():
    catalog = load_service_catalog(CATALOG)
    assert get_oncall_command_for_target("RevPro Support", catalog) == "@zsrebot oncall RevPro support"


def test_unknown_service_does_not_produce_command():
    catalog = load_service_catalog(CATALOG)
    assert get_oncall_command_for_target("Default_Agent", catalog) is None


def test_command_registry_loads_command_text_template_shape():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as file:
        file.write(
            """
commands:
  - command_id: sample
    command_text_template: "@zsrebot oncall RevPro support"
    target: RevPro Support
    source_service_id: revpro-support
    requires_human_approval: true
"""
        )
        file.flush()
        registry = load_command_registry(file.name, catalog=None)
    assert registry[0].command == "@zsrebot oncall RevPro support"
