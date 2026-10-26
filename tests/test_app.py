"""Streamlit smoke tests for the FireWise interface."""

from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_app_renders_all_six_tabs_without_loaded_policy() -> None:
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    app = AppTest.from_file(str(app_path), default_timeout=30).run()

    assert not app.exception
    assert [tab.label for tab in app.tabs] == [
        "Home",
        "Dashboard",
        "Problems",
        "Network Map",
        "Optimizer",
        "Report",
    ]
    assert any(button.label == "Load Demo Data" for button in app.button)


def test_app_load_demo_data_populates_dashboard_and_findings() -> None:
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    app = AppTest.from_file(str(app_path), default_timeout=30).run()
    app.button[0].click().run()

    assert not app.exception
    assert any("40 rules" in item.value for item in app.success)


def test_report_tab_exposes_download_after_loading_demo() -> None:
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    app = AppTest.from_file(str(app_path), default_timeout=30).run()
    app.button[0].click().run()

    assert not app.exception
    report_tab = app.tabs[5]
    assert any(
        button.label == "Download HTML report" for button in report_tab.download_button
    )
    assert any(
        "current policy score and findings" in item.value for item in report_tab.caption
    )
