"""Entry point for running the AcmeCorp mock API server."""

from .app import app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_mock_api(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn
    uvicorn.run(app, host=host, port=port)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the AcmeCorp mock API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run_mock_api(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
