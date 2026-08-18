"""Application entry point.

Start with:
    python -m app
    python -m app --port 9090
"""

from __future__ import annotations

import argparse
import socket
import sys


def _port_in_use(port: int) -> bool:
    """Return True if the given TCP port is already bound on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return False
        except OSError:
            return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prompt Injection Detector — local demo server"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)",
    )
    args = parser.parse_args()
    port: int = args.port

    if not (1 <= port <= 65535):
        print(f"Error: port {port} is out of valid range (1–65535).", file=sys.stderr)
        sys.exit(1)

    if _port_in_use(port):
        print(
            f"Error: port {port} is already in use. "
            "Please free the port or choose a different one with --port.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Lazy import so argparse errors are fast
    import uvicorn
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    import os

    from app.api.routes import router

    app = FastAPI(title="Prompt Injection Detector", version="1.0.0")
    app.include_router(router)

    # Serve static assets (CSS, JS)
    static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
    static_dir = os.path.abspath(static_dir)
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    print(f"\n  Prompt Injection Detector")
    print(f"  Dashboard: http://localhost:{port}")
    print(f"  Press Ctrl+C to stop\n")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
