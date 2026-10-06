#!/usr/bin/env python3
"""Entry point: python -m zta.serve [--host 0.0.0.0] [--port 8080] [--db zta.db]"""

from __future__ import annotations

import argparse

from .api import DEFAULT_DB, make_server


def main() -> None:
    parser = argparse.ArgumentParser(description="Zero-trust continuous risk engine")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite path (':memory:' for ephemeral)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    httpd = make_server(args.host, args.port, args.db, args.verbose)
    print(f"zero-trust risk engine listening on http://{args.host}:{args.port}")
    print(f"policy store: {args.db} · session console at /")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.store.close()


if __name__ == "__main__":
    main()
