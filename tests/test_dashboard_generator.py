"""Tests for ``aegistrace.dashboard_generator``."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from aegistrace.dashboard_generator import (
    _build_ioc_table,
    _build_subplots,
    _mock_threats,
    _safe_first,
    generate_dashboard,
)


@pytest.fixture
def sample_predictions() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "date": pd.date_range("2026-07-01", periods=7, freq="D"),
            "predicted_threats": [3.0, 5.0, 7.5, 11.0, 4.0, 6.0, 9.0],
            "risk_level": ["Low", "Low", "Medium", "High", "Low", "Medium", "Medium"],
        }
    )


def test_safe_first_returns_mode() -> None:
    series = pd.Series(["a", "b", "a", "c"])
    assert _safe_first(series) == "a"


def test_safe_first_returns_default_for_empty() -> None:
    assert _safe_first(pd.Series([], dtype=object), default="X") == "X"


def test_mock_threats_have_required_fields() -> None:
    threats = _mock_threats()
    assert len(threats) == 2
    for t in threats:
        assert all(k in t for k in ["title", "summary_nlp", "entities", "sector", "threat_type", "source"])


def test_build_subplots_returns_figure_with_data(sample_threats: list[dict], sample_predictions: pd.DataFrame) -> None:
    df = pd.DataFrame(sample_threats)
    df["threat_type"] = ["Ransomware", "Phishing", "Vulnerability"]
    df["entities"] = [["ACME"], ["Bank"], ["Apache"]]
    fig = _build_subplots(df, sample_predictions)
    # Subplot should always have at least the forecast trace.
    assert len(fig.data) >= 1


def test_build_ioc_table_returns_empty_string_for_none() -> None:
    assert _build_ioc_table(None) == ""


def test_build_ioc_table_renders_html() -> None:
    iocs = [
        {
            "indicator": "1.2.3.4",
            "type": "ip",
            "reputation": "high",
            "country": "US",
            "active": "active",
            "campaigns": ["botnet"],
            "details_url": "https://example.com",
        }
    ]
    html = _build_ioc_table(iocs)
    assert "<table" in html
    assert "1.2.3.4" in html


def test_generate_dashboard_writes_html_file(
    sample_threats: list[dict], sample_predictions: pd.DataFrame, tmp_path: Path
) -> None:
    df_threats = pd.DataFrame(sample_threats)
    df_threats["threat_type"] = ["Ransomware", "Phishing", "Vulnerability"]
    df_threats["entities"] = [["ACME"], ["Bank"], ["Apache"]]
    threats = df_threats.to_dict(orient="records")

    out = tmp_path / "dash.html"
    path = generate_dashboard(threats, sample_predictions, iocs_enriched=[], output_file=str(out))
    assert Path(path).exists()
    content = out.read_text(encoding="utf-8")
    assert "<html" in content
    assert "AegisTrace Dashboard" in content


def test_generate_dashboard_uses_mock_threats_when_empty(sample_predictions: pd.DataFrame, tmp_path: Path) -> None:
    out = tmp_path / "empty.html"
    path = generate_dashboard([], sample_predictions, output_file=str(out))
    assert Path(path).exists()
    content = out.read_text(encoding="utf-8")
    assert "Mock" in content or "mock" in content.lower() or "Total Threats" in content


def test_generate_dashboard_handles_missing_iocs(sample_threats: list[dict], sample_predictions: pd.DataFrame, tmp_path: Path) -> None:
    df_threats = pd.DataFrame(sample_threats)
    df_threats["threat_type"] = ["Ransomware", "Phishing", "Vulnerability"]
    df_threats["entities"] = [["ACME"], ["Bank"], ["Apache"]]
    threats = df_threats.to_dict(orient="records")

    out = tmp_path / "no_iocs.html"
    generate_dashboard(threats, sample_predictions, iocs_enriched=None, output_file=str(out))
    content = out.read_text(encoding="utf-8")
    assert "No indicators extracted" in content


def test_generate_dashboard_with_enriched_iocs(
    sample_threats: list[dict], sample_predictions: pd.DataFrame, tmp_path: Path
) -> None:
    df_threats = pd.DataFrame(sample_threats)
    df_threats["threat_type"] = ["Ransomware", "Phishing", "Vulnerability"]
    df_threats["entities"] = [["ACME"], ["Bank"], ["Apache"]]
    threats = df_threats.to_dict(orient="records")

    enriched = [
        {
            "indicator": "1.2.3.4",
            "type": "ip",
            "reputation": "AbuseIPDB:80/100",
            "country": "RU",
            "active": "active",
            "campaigns": ["botnet", "c2"],
            "details_url": "https://abuseipdb.com/check/1.2.3.4",
        }
    ]
    out = tmp_path / "with_iocs.html"
    generate_dashboard(threats, sample_predictions, iocs_enriched=enriched, output_file=str(out))
    content = out.read_text(encoding="utf-8")
    assert "1.2.3.4" in content
    assert "botnet, c2" in content
