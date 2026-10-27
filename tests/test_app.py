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
    assert any(
        item.label == "Ignore rules that never fire (recommended)"
        and item.value
        for item in app.checkbox
    )
    assert any(
        item.label == "Keep logged deny rules" and item.value
        for item in app.checkbox
    )
    assert any(
        item.label == "Keep all deny rules" and not item.value
        for item in app.checkbox
    )


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


def test_app_shows_csv_normalization_warnings_on_home() -> None:
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    app = AppTest.from_file(str(app_path), default_timeout=30).run()
    content = (
        "id,src_zone,dst_zone,src_ip,dst_ip,service,action,log\n"
        "r1,LAN,WAN,10.0.0.5/24,192.0.2.0/24,https,permit,true\n"
    )

    app.file_uploader[0].set_value(("rules.csv", content.encode(), "text/csv")).run()

    assert not app.exception
    assert any("has host bits set; treated as 10.0.0.0/24." in item.value for item in app.warning)
