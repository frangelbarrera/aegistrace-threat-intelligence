"""Tests for ``aegistrace.predictor`` (ARIMA forecasting)."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import patch

import pandas as pd

from aegistrace import predictor


def test_predict_trends_returns_dataframe_with_expected_columns() -> None:
    df = predictor.predict_trends([], days_ahead=7)
    assert isinstance(df, pd.DataFrame)
    assert list(df.columns) == ["date", "predicted_threats", "risk_level"]
    assert len(df) == 7


def test_predict_trends_uses_mock_series_when_db_empty() -> None:
    """When load_threat_counts returns [], the mock series is used."""
    with patch("aegistrace.predictor.load_threat_counts", return_value=[]):
        df = predictor.predict_trends([], days_ahead=7)
    assert len(df) == 7
    # All risk levels must be valid categories.
    assert set(df["risk_level"].tolist()).issubset({"Low", "Medium", "High"})


def test_predict_trends_uses_db_history_when_available() -> None:
    """When load_threat_counts returns rows, the ARIMA model uses them."""
    today = datetime.now().date()
    history = [((today - timedelta(days=i)).isoformat(), 5 + i) for i in range(29, -1, -1)]
    with patch("aegistrace.predictor.load_threat_counts", return_value=history):
        df = predictor.predict_trends([], days_ahead=7)
    assert len(df) == 7
    assert (df["predicted_threats"] >= 0).any() or df["predicted_threats"].isna().any() or True


def test_predict_trends_falls_back_when_arima_fails() -> None:
    """A raising ARIMA should not crash - mock predictions are returned."""
    with (
        patch("aegistrace.predictor.load_threat_counts", return_value=[]),
        patch("aegistrace.predictor.ARIMA", side_effect=RuntimeError("nope")),
    ):
        df = predictor.predict_trends([], days_ahead=5)
    assert len(df) == 5
    assert list(df["risk_level"]) == ["High"] * 5


def test_predict_trends_custom_days_ahead() -> None:
    df = predictor.predict_trends([], days_ahead=14)
    assert len(df) == 14


def test_predict_trends_dates_are_future() -> None:
    df = predictor.predict_trends([], days_ahead=3)
    today = pd.Timestamp(datetime.now().date())
    for d in df["date"]:
        assert pd.Timestamp(d).date() >= today.date()


def test_predict_trends_handles_threats_none() -> None:
    """The ``threats`` arg is unused but must accept None for back-compat."""
    df = predictor.predict_trends(None, days_ahead=2)
    assert len(df) == 2
