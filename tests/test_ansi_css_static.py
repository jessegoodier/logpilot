"""Static checks for ANSI/error CSS shipped in index.html (no live server needed)."""

from pathlib import Path

INDEX_HTML = Path(__file__).resolve().parents[1] / "src" / "index.html"


def test_ansi_and_error_css_classes_in_index_html():
    html = INDEX_HTML.read_text(encoding="utf-8")

    required = [
        ".ansi-red",
        ".ansi-green",
        ".ansi-blue",
        ".ansi-yellow",
        ".ansi-magenta",
        ".ansi-cyan",
        ".ansi-white",
        ".ansi-black",
        ".ansi-bright-red",
        ".ansi-bright-green",
        ".ansi-bright-blue",
        ".log-error",
        ".retry-button",
        ".dark .ansi-red",
        ".dark .ansi-green",
    ]

    missing = [cls for cls in required if cls not in html]
    assert not missing, f"Missing CSS selectors in index.html: {missing}"
