from __future__ import annotations

from ic_copilot.product_knowledge import load_product_knowledge
from ic_copilot.runtime_config import ProductRuntimeConfig
from ic_copilot.schemas import CommandRegistryEntry, DecisionMoment, ServiceCatalogEntry


def load_product_catalog(config: ProductRuntimeConfig) -> list[ServiceCatalogEntry]:
    return load_product_knowledge(config.product_knowledge_path).catalog


def load_product_command_registry(
    config: ProductRuntimeConfig,
    catalog: list[ServiceCatalogEntry],
) -> list[CommandRegistryEntry]:
    _ = catalog
    return load_product_knowledge(config.product_knowledge_path).command_registry


def load_product_decision_moments(config: ProductRuntimeConfig) -> list[DecisionMoment]:
    return load_product_knowledge(config.product_knowledge_path).decision_moments
