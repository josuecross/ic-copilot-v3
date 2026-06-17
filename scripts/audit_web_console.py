from __future__ import annotations

import argparse
from pathlib import Path

from ic_copilot.web.app import create_app
from ic_copilot.web.safety import format_web_safety_audit, run_web_safety_audit


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit the local IC Copilot web console safety boundaries.")
    parser.add_argument("--output-json", default=".ic_copilot/web_audit/web_audit.json")
    parser.add_argument("--output-md", default=".ic_copilot/web_audit/web_audit.md")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run_web_safety_audit(create_app())
    output_json = Path(args.output_json)
    output_md = Path(args.output_md)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(result.model_dump_json(indent=2))
    output_md.write_text(format_web_safety_audit(result))
    print(format_web_safety_audit(result))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
