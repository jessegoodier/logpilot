import pytest
import requests

from tests.settings import APP_BASE_URL

E2E_MODULES = {
    "test_app_playwright",
    "test_auth_playwright",
    "test_frontend_ansi",
    "test_integration_ansi",
}


@pytest.fixture(scope="session")
def app_base_url():
    """Base URL for the running logPilot instance under test."""
    return APP_BASE_URL


@pytest.fixture(scope="session")
def live_app(app_base_url):
    """Skip when logPilot is not reachable (unit tests still run)."""
    try:
        response = requests.get(app_base_url, timeout=2)
        response.raise_for_status()
    except (requests.RequestException, OSError) as exc:
        pytest.skip(f"logPilot not available at {app_base_url}: {exc}")
    return app_base_url


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Configure browser context for tests."""
    return {
        **browser_context_args,
        "ignore_https_errors": True,
    }


@pytest.fixture(scope="session")
def browser_type_launch_args(live_app):
    """Require a live app before launching browsers; optimize for CI."""
    return {
        "headless": True,
        "args": [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-web-security",
        ],
    }


@pytest.fixture(autouse=True)
def _e2e_requires_live_app(request):
    """Integration/e2e modules need a running logPilot instance."""
    if request.node.get_closest_marker("e2e"):
        request.getfixturevalue("live_app")


def pytest_collection_modifyitems(config, items):
    """Mark modules that talk to a live logPilot instance."""
    e2e_marker = pytest.mark.e2e
    for item in items:
        module_name = item.module.__name__.rsplit(".", 1)[-1]
        if module_name in E2E_MODULES:
            item.add_marker(e2e_marker)
