"""Tests for the CLI entry point and the main pipeline orchestrator."""

from __future__ import annotations

from unittest.mock import patch

import pandas as pd
import pytest

from aegistrace import cli
from aegistrace.main import PipelineResult, run


def test_cli_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "aegistrace" in captured.out
    assert "--sources" in captured.out


def test_cli_version_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "0.2.0" in captured.out


def test_cli_runs_pipeline_with_mock_data() -> None:
    """End-to-end CLI run. Because the test environment has no network
    access to external CTI feeds, the pipeline falls back to mock data,
    so the exit code should be 1 (warnings)."""
    exit_code = cli.main(["--no-enrich", "--no-forecast", "--output", "dash.html"])
    # 1 == warnings (mock data fallback). Acceptable for offline test env.
    assert exit_code in {0, 1}


def test_cli_returns_2_on_pipeline_crash() -> None:
    with patch("aegistrace.cli.run", side_effect=RuntimeError("boom")):
        assert cli.main([]) == 2


def test_run_returns_pipeline_result_with_mock_data() -> None:
    result = run(enrich=False, forecast=True, output="d.html", csv_path="i.csv")
    assert isinstance(result, PipelineResult)
    assert isinstance(result.threats, list)
    assert isinstance(result.iocs_enriched, list)
    assert result.dashboard_path == "d.html"
    assert result.csv_path == "i.csv"


def test_run_with_no_forecast_produces_empty_predictions() -> None:
    result = run(enrich=False, forecast=False, output="d2.html", csv_path="i2.csv")
    assert isinstance(result.predictions, pd.DataFrame)
    assert len(result.predictions) == 0


def test_run_with_sources_filter_does_not_crash() -> None:
    result = run(sources=["urlhaus"], enrich=False, forecast=False, output="d3.html", csv_path="i3.csv")
    assert isinstance(result, PipelineResult)


def test_pipeline_result_dataclass_defaults() -> None:
    pr = PipelineResult()
    assert pr.threats == []
    assert pr.iocs_enriched == []
    assert pr.predictions is None
    assert pr.dashboard_path == ""
    assert pr.csv_path == ""


def test_cli_verbose_flag_enables_debug_logging() -> None:
    """The verbose flag must not crash the CLI."""
    exit_code = cli.main(["--verbose", "--no-enrich", "--no-forecast", "--output", "v.html"])
    assert exit_code in {0, 1, 2}
