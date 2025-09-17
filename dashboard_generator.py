# dashboard_generator.py
import pandas as pd
import plotly.express as px
from plotly.subplots import make_subplots

def _safe_first(series, default="N/A"):
    """
    Safely return the first mode (most frequent value) of a pandas Series.
    If the Series is empty or an error occurs, return the provided default.
    """
    try:
        return series.mode().iloc[0]
    except Exception:
        return default

def generate_dashboard(threats, predictions, iocs_enriched=None, output_file="dashboard.html"):
    """
    Generate the AegisTrace HTML dashboard with KPIs, charts, and tables.

    Parameters:
        threats (list of dict): List of processed threat records.
        predictions (DataFrame): Forecasted threat trends.
        iocs_enriched (list of dict, optional): Enriched Indicators of Compromise.
        output_file (str): Path to save the generated HTML file.
    """

    # === Fallback: use mock threats if the list is empty ===
    if not threats:
        print("[!] No threats collected. Using mock data for dashboard.")
        threats = [
            {
                "title": "Mock Ransomware Attack on Finance Sector",
                "summary_nlp": "Simulated ransomware incident affecting major bank systems.",
                "entities": ["MockCorp"],
                "sector": "Finance",
                "threat_type": "Ransomware",
                "source": "MockData"
            },
            {
                "title": "Mock Phishing Campaign Targets Healthcare",
                "summary_nlp": "Simulated phishing emails sent to hospital staff.",
                "entities": ["MockBank"],
                "sector": "Healthcare",
                "threat_type": "Phishing",
                "source": "MockData"
            }
        ]

    df_threats = pd.DataFrame(threats)

    # === KPIs ===
    total_threats = len(df_threats)
    top_sector = _safe_first(df_threats["sector"]) if "sector" in df_threats.columns else "N/A"
    top_entity = "N/A"
    top_threat_type = _safe_first(df_threats["threat_type"]) if "threat_type" in df_threats.columns else "N/A"

    # Determine the most frequent entity if available
    if "entities" in df_threats.columns and not df_threats.empty:
        try:
            all_entities = [ent for ents in df_threats["entities"] for ent in (ents or [])]
            if all_entities:
                top_entity = pd.Series(all_entities).mode().iloc[0]
        except Exception:
            pass

    # === Chart 1: Threats by Sector ===
    if "sector" in df_threats.columns and not df_threats.empty:
        sector_counts = df_threats.groupby("sector").size().reset_index(name="count")
        fig1 = px.bar(sector_counts, x="sector", y="count", title="Threats by Sector", color="sector")
    else:
        fig1 = px.bar(title="Threats by Sector (No data)")

    # === Chart 2: 7-Day Threat Forecast ===
    fig2 = px.line(predictions, x="date", y="predicted_threats", color="risk_level", title="7-Day Threat Forecast")

    # === Chart 3: Threats by Type ===
    if "threat_type" in df_threats.columns and not df_threats.empty:
        type_counts = df_threats.groupby("threat_type").size().reset_index(name="count")
        fig3 = px.bar(type_counts, x="threat_type", y="count", title="Threats by Type", color="threat_type")
    else:
        fig3 = px.bar(title="Threats by Type (No data)")

    # === Combine charts into a single figure ===
    fig = make_subplots(
        rows=3, cols=1,
        subplot_titles=("Threats by Sector", "7-Day Forecast", "Threats by Type")
    )
    if fig1.data: fig.add_trace(fig1.data[0], row=1, col=1)
    if fig2.data: fig.add_trace(fig2.data[0], row=2, col=1)
    if fig3.data: fig.add_trace(fig3.data[0], row=3, col=1)
    fig.update_layout(height=1000, title_text="AegisTrace Dashboard")

    # === IoCs Table (enriched) ===
    ioc_table_html = ""
    if iocs_enriched:
        df_ioc = pd.DataFrame(iocs_enriched)
        # Select only relevant columns if they exist
        cols = []
        for c in ["indicator", "type", "reputation", "country", "active", "campaigns", "details_url"]:
            if c in df_ioc.columns:
                cols.append(c)
        # Convert list-type columns to comma-separated strings
        if "campaigns" in df_ioc.columns:
            df_ioc["campaigns"] = df_ioc["campaigns"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
        # Limit to first 20 rows for display
        ioc_table_html = df_ioc[cols].head(20).to_html(index=False, escape=False)

    # === HTML Template ===
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AegisTrace Dashboard</title>
        <meta charset="utf-8" />
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 24px; }}
            h1, h2, h3 {{ margin-bottom: 8px; }}
            ul {{ line-height: 1.6; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; }}
            th {{ background: #f4f6f8; }}
            .section {{ margin-top: 24px; }}
        </style>
    </head>
    <body>
    <h1>AegisTrace Dashboard</h1>
    <h3>KPIs</h3>
    <ul>
        <li>Total Threats: {total_threats}</li>
        <li>Top Sector: {top_sector}</li>
        <li>Top Entity: {top_entity}</li>
        <li>Top Threat Type: {top_threat_type}</li>
    </ul>
    {fig.to_html(full_html=False, include_plotlyjs='cdn')}
    <div class="section">
      <h2>Recent Threats</h2>
      {df_threats[['title', 'summary_nlp', 'entities', 'sector', 'threat_type', 'source']].head(15).to_html(index=False)}
    </div>
    <div class="section">
      <h2>Indicators of Compromise</h2>
      <p>Enrichment is best-effort. Missing API keys or network limits may reduce details.</p>
      {ioc_table_html or "<em>No indicators extracted.</em>"}
    </div>
    </body>
    </html>
    """

    # === Save HTML file ===
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Dashboard saved as {output_file}")
