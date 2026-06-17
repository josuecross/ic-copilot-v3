from __future__ import annotations

import argparse
import os
from pathlib import Path

import uvicorn


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local IC Copilot web console.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host. Defaults to localhost only.")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--db-path", default=".ic_copilot/web.sqlite3")
    parser.add_argument(
        "--allow-non-localhost-dangerous-dev-only",
        action="store_true",
        help="Required to bind to anything other than 127.0.0.1/localhost.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    safe_hosts = {"127.0.0.1", "localhost", "::1"}
    if args.host not in safe_hosts and not args.allow_non_localhost_dangerous_dev_only:
        print(
            "Refusing to bind outside localhost. Re-run with "
            "--allow-non-localhost-dangerous-dev-only only for deliberate local dev exposure."
        )
        return 2
    if args.host not in safe_hosts:
        print("WARNING: non-localhost bind requested. This console is not a production web app.")
    Path(args.db_path).parent.mkdir(parents=True, exist_ok=True)
    os.environ["IC_COPILOT_WEB_DB_PATH"] = args.db_path
    if args.reload:
        uvicorn.run(
            "ic_copilot.web.app:create_app",
            factory=True,
            host=args.host,
            port=args.port,
            reload=True,
            log_level="info",
        )
    else:
        from ic_copilot.web.app import create_app

        uvicorn.run(create_app(db_path=args.db_path), host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
