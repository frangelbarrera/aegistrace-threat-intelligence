"""Command-line interface for AegisTrace.

Run as ``python -m aegistrace`` or via the ``aegistrace`` console script
(once the package is pip-installed).

Exit codes:
    0 - success
    1 - warnings (e.g. some sources failed but pipeline finished)
    2 - error (pipeline crashed)
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from . import __version__
from .logging_config import get_logger
from .main import run

logger = get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegistrace",
        description="AegisTrace - Cyber Threat Intelligence pipeline.",
    )
    parser.add_argument("--version", action="version", version=f"aegistrace {__version__}")
    parser.add_argument(
        "--sources",
        type=str,
        default=None,
        help="Comma-separated subset of sources: otx,rss,urlhaus,malwarebazaar,feodotracker",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip IoC enrichment (faster, no external API calls).",
    )
    parser.add_argument(
        "--no-forecast",
        action="store_true",
        help="Skip ARIMA forecasting.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="dashboard.html",
        help="HTML dashboard output path (default: dashboard.html).",
    )
    parser.add_argument(
        "--csv",
        type=str,
        default="iocs_enriched.csv",
        help="Enriched IoCs CSV output path (default: iocs_enriched.csv).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code (0/1/2).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    sources = [s.strip() for s in args.sources.split(",")] if args.sources else None

    try:
        result = run(
            sources=sources,
            enrich=not args.no_enrich,
            forecast=not args.no_forecast,
            output=args.output,
            csv_path=args.csv,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Pipeline crashed: %s", exc, exc_info=True)
        return 2

    threats_count = len(result.threats)
    iocs_count = len(result.iocs_enriched)
    logger.info(
        "Done. threats=%d, iocs=%d, dashboard=%s, csv=%s",
        threats_count,
        iocs_count,
        result.dashboard_path,
        result.csv_path,
    )
    print(f"[+] Threats: {threats_count} | IoCs: {iocs_count}")
    print(f"[+] Dashboard: {result.dashboard_path}")
    print(f"[+] CSV: {result.csv_path}")

    # Exit 1 if the pipeline produced no real threats (mock data fallback).
    if threats_count == 0 or all(t.get("source") == "MockData" for t in result.threats):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
