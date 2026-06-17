#!/usr/bin/env python
from __future__ import annotations

import argparse
import json

from ic_copilot.error_sanitizer import sanitize_user_facing_error
from ic_copilot.product_smoke import run_product_smoke


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one normal product-path IC Copilot smoke.")
    parser.add_argument("--incident", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--knowledge-dir", default=None)
    args = parser.parse_args()
    try:
        payload = run_product_smoke(args.incident, output_json=args.output_json, knowledge_dir=args.knowledge_dir)
    except Exception as exc:
        print(sanitize_user_facing_error(exc))
        return 1
    print(json.dumps({"ok": payload["ok"], "verifier_status": payload["verifier_status"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
