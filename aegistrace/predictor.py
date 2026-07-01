"""ARIMA-based threat trend forecasting.

When the local SQLite database has >= a few days of historical threat
counts the predictor fits an ARIMA(1, 1, 1) model and forecasts the next
``days_ahead`` days. If history is empty or the model fails the function
falls back to a deterministic synthetic series so the dashboard can still
render.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pandas as pd
from statsmodels.tsa.arima.model import ARIMA

from .logging_config import get_logger
from .storage import load_threat_counts

logger = get_logger(__name__)


def _series_from_history(hist_counts: list[tuple[str, int]]) -> pd.Series:
    """Build a daily-count pandas Series from DB rows."""
    dates = [datetime.strptime(d, "%Y-%m-%d") for d, _ in hist_counts]
    counts = [c for _, c in hist_counts]
    return pd.Series(counts, index=pd.to_datetime(dates))


def _mock_series() -> pd.Series:
    """Deterministic synthetic 30-day series used as a fallback."""
    dates = pd.date_range(end=datetime.now(), periods=30, freq="D")
    return pd.Series([4 + i * 0.3 + (i % 5) * 2 for i in range(30)], index=dates)


def predict_trends(
    threats: list[dict[str, Any]] | None = None, days_ahead: int = 7
) -> pd.DataFrame:
    """Forecast threat counts for the next ``days_ahead`` days.

    Args:
        threats: Current threat list. Kept for API compatibility but not
            used directly; the predictor reads historical counts from the
            database instead.
        days_ahead: Number of days to forecast.

    Returns:
        DataFrame with columns ``date`` (datetime), ``predicted_threats``
        (float) and ``risk_level`` (categorical: ``"Low"`` / ``"Medium"``
        / ``"High"``).
    """
    del threats  # kept for backward compatibility

    hist_counts = load_threat_counts(days=30)
    series = _series_from_history(hist_counts) if hist_counts else _mock_series()

    try:
        # Enforce a daily frequency so statsmodels stops warning about
        # missing freq information.
        series = series.asfreq("D")
        model = ARIMA(series, order=(1, 1, 1))
        model_fit = model.fit()
        forecast = model_fit.forecast(steps=days_ahead)
        forecast_dates = pd.date_range(
            start=datetime.now() + timedelta(days=1), periods=days_ahead, freq="D"
        )
        pred_df = pd.DataFrame({"date": forecast_dates, "predicted_threats": forecast.values})
        pred_df["risk_level"] = pd.cut(
            pred_df["predicted_threats"],
            bins=[-float("inf"), 5, 10, float("inf")],
            labels=["Low", "Medium", "High"],
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("ARIMA failed: %s. Using mock predictions.", exc)
        forecast_dates = pd.date_range(
            start=datetime.now() + timedelta(days=1), periods=days_ahead, freq="D"
        )
        pred_df = pd.DataFrame(
            {
                "date": forecast_dates,
                "predicted_threats": [18 + i * -0.1 for i in range(days_ahead)],
                "risk_level": ["High"] * days_ahead,
            }
        )
    return pred_df
