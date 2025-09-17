# predictor.py
import pandas as pd
from datetime import datetime, timedelta
from statsmodels.tsa.arima.model import ARIMA
from storage import load_threat_counts

def predict_trends(threats, days_ahead=7):
    """
    Predict threat trends for the next N days using ARIMA time series forecasting.

    Args:
        threats (list of dict): Current list of threats (not directly used here, but kept for flexibility).
        days_ahead (int): Number of days to forecast ahead.

    Returns:
        pandas.DataFrame: DataFrame containing:
            - date: forecast date
            - predicted_threats: predicted number of threats
            - risk_level: categorical risk level ("Low", "Medium", "High")
    """

    # === Try to use real historical data from the database ===
    hist_counts = load_threat_counts(days=30)
    if hist_counts:
        # Convert DB results into a pandas Series
        dates = [datetime.strptime(d, "%Y-%m-%d") for d, _ in hist_counts]
        counts = [c for _, c in hist_counts]
        series = pd.Series(counts, index=pd.to_datetime(dates))
    else:
        # === Fallback: generate mock data if no history is available ===
        dates = pd.date_range(end=datetime.now(), periods=30)
        series = pd.Series([4 + i * 0.3 + (i % 5) * 2 for i in range(30)], index=dates)

    try:
        # === Fit ARIMA model ===
        model = ARIMA(series, order=(1, 1, 1))
        model_fit = model.fit()

        # === Forecast for the specified number of days ===
        forecast = model_fit.forecast(steps=days_ahead)
        forecast_dates = pd.date_range(start=datetime.now() + timedelta(days=1), periods=days_ahead)

        # === Build prediction DataFrame ===
        pred_df = pd.DataFrame({
            "date": forecast_dates,
            "predicted_threats": forecast.values
        })

        # Categorize risk level based on predicted threat counts
        pred_df["risk_level"] = pd.cut(
            pred_df["predicted_threats"],
            bins=[0, 5, 10, float("inf")],
            labels=["Low", "Medium", "High"]
        )

    except Exception as e:
        # === Fallback: use static mock predictions if ARIMA fails ===
        print(f"[!] ARIMA failed: {e}. Using mock predictions.")
        forecast_dates = pd.date_range(start=datetime.now() + timedelta(days=1), periods=days_ahead)
        pred_df = pd.DataFrame({
            "date": forecast_dates,
            "predicted_threats": [18 + i * -0.1 for i in range(days_ahead)],
            "risk_level": ["High"] * days_ahead
        })

    return pred_df

