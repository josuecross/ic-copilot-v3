#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ic_copilot.provider_health import check_product_provider_health
from ic_copilot.runtime_diagnostics import collect_provider_runtime_diagnostics, format_provider_diagnostics_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the configured product provider through the product adapter path.")
    parser.add_argument("--config", default=None)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    args = parser.parse_args()

    diag = collect_provider_runtime_diagnostics(args.config)
    health = check_product_provider_health(args.config)
    payload = {
        "diagnostics": diag.model_dump(mode="json"),
        "health": health.model_dump(mode="json"),
    }
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, indent=2, default=str))
    output_md.write_text(
        format_provider_diagnostics_markdown(diag)
        + "\n# Provider Health\n\n"
        + f"- status: {health.status}\n"
        + f"- provider: {health.provider}\n"
        + f"- model: {health.model}\n"
        + f"- latency_ms: {health.latency_ms if health.latency_ms is not None else 'n/a'}\n"
        + f"- fingerprint: {health.fingerprint or 'n/a'}\n"
        + f"- request_id: {health.request_id or 'n/a'}\n"
        + f"- safe_message: {health.safe_message}\n"
    )
    print(health.safe_message)
    return 0 if health.status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
