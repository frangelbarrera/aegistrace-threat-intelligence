"""Interactive Plotly dashboard generator.

Builds an HTML file with KPIs, three charts (threats by sector, 7-day
forecast, threats by type) and tables for recent threats + enriched IoCs.
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.express as px
from plotly.subplots import make_subplots

from .logging_config import get_logger

logger = get_logger(__name__)


def _safe_first(series: pd.Series, default: str = "N/A") -> str:
    """Return the most frequent value of a Series, or ``default``."""
    try:
        return str(series.mode().iloc[0])
    except Exception:  # noqa: BLE001
        return default


def _mock_threats() -> list[dict[str, Any]]:
    """Fallback threats used when the pipeline produced nothing."""
    return [
        {
            "title": "Mock Ransomware Attack on Finance Sector",
            "summary_nlp": "Simulated ransomware incident affecting major bank systems.",
            "entities": ["MockCorp"],
            "sector": "Finance",
            "threat_type": "Ransomware",
            "source": "MockData",
        },
        {
            "title": "Mock Phishing Campaign Targets Healthcare",
            "summary_nlp": "Simulated phishing emails sent to hospital staff.",
            "entities": ["MockBank"],
            "sector": "Healthcare",
            "threat_type": "Phishing",
            "source": "MockData",
        },
    ]


def _build_subplots(df_threats: pd.DataFrame, predictions: pd.DataFrame) -> Any:
    """Compose the three-chart subplot figure."""
    fig1 = (
        px.bar(
            df_threats.groupby("sector").size().reset_index(name="count"),
            x="sector",
            y="count",
            title="Threats by Sector",
            color="sector",
        )
        if "sector" in df_threats.columns and not df_threats.empty
        else px.bar(title="Threats by Sector (No data)")
    )

    fig2 = px.line(
        predictions, x="date", y="predicted_threats", color="risk_level", title="7-Day Threat Forecast"
    )

    fig3 = (
        px.bar(
            df_threats.groupby("threat_type").size().reset_index(name="count"),
            x="threat_type",
            y="count",
            title="Threats by Type",
            color="threat_type",
        )
        if "threat_type" in df_threats.columns and not df_threats.empty
        else px.bar(title="Threats by Type (No data)")
    )

    fig = make_subplots(
        rows=3, cols=1, subplot_titles=("Threats by Sector", "7-Day Forecast", "Threats by Type")
    )
    if fig1.data:
        fig.add_trace(fig1.data[0], row=1, col=1)
    if fig2.data:
        fig.add_trace(fig2.data[0], row=2, col=1)
    if fig3.data:
        fig.add_trace(fig3.data[0], row=3, col=1)
    fig.update_layout(height=1000, title_text="AegisTrace Dashboard")
    return fig


def _build_ioc_table(iocs_enriched: list[dict[str, Any]] | None) -> str:
    """Render the IoC table HTML (empty string when no IoCs)."""
    if not iocs_enriched:
        return ""
    df_ioc = pd.DataFrame(iocs_enriched)
    cols = [c for c in ["indicator", "type", "reputation", "country", "active", "campaigns", "details_url"] if c in df_ioc.columns]
    if "campaigns" in df_ioc.columns:
        df_ioc["campaigns"] = df_ioc["campaigns"].apply(
            lambda x: ", ".join(x) if isinstance(x, list) else x
        )
    return df_ioc[cols].head(20).to_html(index=False, escape=False)


def generate_dashboard(
    threats: list[dict[str, Any]],
    predictions: pd.DataFrame,
    iocs_enriched: list[dict[str, Any]] | None = None,
    output_file: str = "dashboard.html",
) -> str:
    """Generate the AegisTrace HTML dashboard.

    Args:
        threats: List of processed threat records.
        predictions: Forecasted threat trends (DataFrame from
            :func:`aegistrace.predictor.predict_trends`).
        iocs_enriched: Optional list of enriched IoC dicts.
        output_file: Path of the HTML file to write.

    Returns:
        The path of the written file.
    """
    if not threats:
        logger.warning("No threats collected. Using mock data for dashboard.")
        threats = _mock_threats()

    df_threats = pd.DataFrame(threats)

    total_threats = len(df_threats)
    top_sector = _safe_first(df_threats["sector"]) if "sector" in df_threats.columns else "N/A"
    top_threat_type = (
        _safe_first(df_threats["threat_type"]) if "threat_type" in df_threats.columns else "N/A"
    )

    top_entity = "N/A"
    if "entities" in df_threats.columns and not df_threats.empty:
        try:
            all_entities = [ent for ents in df_threats["entities"] for ent in (ents or [])]
            if all_entities:
                top_entity = str(pd.Series(all_entities).mode().iloc[0])
        except Exception:  # noqa: BLE001
            pass

    fig = _build_subplots(df_threats, predictions)
    ioc_table_html = _build_ioc_table(iocs_enriched)

    # Determine which threat columns are available before rendering the table.
    threat_cols = [
        c for c in ["title", "summary_nlp", "entities", "sector", "threat_type", "source"]
        if c in df_threats.columns
    ]
    threats_table_html = df_threats[threat_cols].head(15).to_html(index=False) if threat_cols else ""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>AegisTrace Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            margin: 24px;
            color: #1f2937;
            background: #ffffff;
        }}
        h1 {{ margin-bottom: 4px; color: #0f172a; }}
        h2, h3 {{ margin-bottom: 8px; color: #1e293b; }}
        ul {{ line-height: 1.6; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 14px; }}
        th, td {{ border: 1px solid #e2e8f0; padding: 8px; text-align: left; }}
        th {{ background: #f1f5f9; }}
        tr:nth-child(even) td {{ background: #f8fafc; }}
        .section {{ margin-top: 32px; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 12px 0 24px; }}
        .kpi {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; }}
        .kpi .label {{ font-size: 12px; text-transform: uppercase; color: #64748b; letter-spacing: 0.05em; }}
        .kpi .value {{ font-size: 20px; font-weight: 600; color: #0f172a; margin-top: 4px; }}
        .note {{ color: #64748b; font-size: 13px; }}
    </style>
</head>
<body>
<h1>AegisTrace Dashboard</h1>
<p class="note">Generated by AegisTrace v0.2.0</p>

<h3>KPIs</h3>
<div class="kpi-grid">
    <div class="kpi"><div class="label">Total Threats</div><div class="value">{total_threats}</div></div>
    <div class="kpi"><div class="label">Top Sector</div><div class="value">{top_sector}</div></div>
    <div class="kpi"><div class="label">Top Entity</div><div class="value">{top_entity}</div></div>
    <div class="kpi"><div class="label">Top Threat Type</div><div class="value">{top_threat_type}</div></div>
</div>

{fig.to_html(full_html=False, include_plotlyjs='cdn')}

<div class="section">
  <h2>Recent Threats</h2>
  {threats_table_html}
</div>

<div class="section">
  <h2>Indicators of Compromise</h2>
  <p class="note">Enrichment is best-effort. Missing API keys or network limits may reduce details.</p>
  {ioc_table_html or "<em>No indicators extracted.</em>"}
</div>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    logger.info("Dashboard saved as %s", output_file)
    return output_file
