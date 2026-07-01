"""Main AegisTrace pipeline.

Orchestrates the full pipeline:

    collect -> NLP -> save -> predict -> extract IoCs -> enrich ->
    save IoCs -> export CSV -> generate dashboard

The :func:`run` function is the single entry point used by both the CLI
(:mod:`aegistrace.cli`) and the thin backward-compatible ``main.py``
shim that lives at the repository root.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from .collectors import fetch_all_sources
from .dashboard_generator import generate_dashboard
from .enricher import enrich_iocs
from .ioc_extractor import extract_iocs
from .logging_config import get_logger
from .nlp_processor import process_nlp
from .predictor import predict_trends
from .storage import init_db, save_iocs, save_threats

logger = get_logger(__name__)


@dataclass
class PipelineResult:
    """Container for everything the pipeline produces in a single run."""

    threats: list[dict[str, Any]] = field(default_factory=list)
    predictions: Any | None = None
    iocs_enriched: list[dict[str, Any]] = field(default_factory=list)
    dashboard_path: str = ""
    csv_path: str = ""


def run(
    sources: list[str] | None = None,
    enrich: bool = True,
    forecast: bool = True,
    output: str = "dashboard.html",
    csv_path: str = "iocs_enriched.csv",
) -> PipelineResult:
    """Run the full AegisTrace pipeline.

    Args:
        sources: Optional subset of source names (see
            :data:`aegistrace.collectors.SOURCE_FETCHERS`). ``None`` runs
            every source.
        enrich: When ``False``, skip the IoC enrichment step.
        forecast: When ``False``, skip the ARIMA forecast step (the
            dashboard's forecast chart will be empty).
        output: HTML dashboard output path.
        csv_path: CSV export path for enriched IoCs.

    Returns:
        :class:`PipelineResult` with references to all produced artefacts.
    """
    logger.info("Starting AegisTrace pipeline")

    init_db()
    threats = fetch_all_sources(sources=sources)
    threats = process_nlp(threats)
    save_threats(threats)

    predictions = predict_trends(threats) if forecast else pd.DataFrame(
        {"date": [], "predicted_threats": [], "risk_level": []}
    )

    iocs = extract_iocs(threats)
    if enrich:
        iocs_enriched = enrich_iocs(iocs)
    else:
        iocs_enriched = [
            {
                **ioc,
                "reputation": "skipped",
                "country": None,
                "active": "unknown",
                "campaigns": [],
                "details_url": None,
                "note": "enrichment skipped by flag",
            }
            for ioc in iocs
        ]
    save_iocs(iocs_enriched)

    pd.DataFrame(iocs_enriched).to_csv(csv_path, index=False)
    logger.info("IoCs exported to %s", csv_path)

    dashboard_path = generate_dashboard(threats, predictions, iocs_enriched=iocs_enriched, output_file=output)

    logger.info("AegisTrace pipeline complete")
    return PipelineResult(
        threats=threats,
        predictions=predictions,
        iocs_enriched=iocs_enriched,
        dashboard_path=dashboard_path,
        csv_path=csv_path,
    )
