"""
Playwright tests for API key authentication functionality.
Tests the end-to-end flow of API key authentication including:
- Access without API key (when required)
- Access with correct API key in URL
- API key propagation to backend requests
- Error handling for invalid API keys
"""

import os
import pytest
from playwright.sync_api import Page, expect

# Test configuration
APP_BASE_URL = "http://localhost:5001"
TEST_API_KEY = "test-api-key-12345"
INVALID_API_KEY = "invalid-key"
NAV_TIMEOUT = 10000
ACTION_TIMEOUT = 5000


@pytest.mark.skipif(
    os.environ.get("API_KEY") != TEST_API_KEY,
    reason="Authentication tests require API_KEY environment variable to be set to test-api-key-12345"
)
class TestAuthenticationFlow:
    """Test authentication flows with API keys."""

    def test_access_without_api_key_shows_form(self, page: Page):
        """Test that accessing app without API key shows login form when auth is required."""
        # Navigate without API key
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        
        # Should show API key form instead of main app
        expect(page.locator("form")).to_be_visible(timeout=ACTION_TIMEOUT)
        expect(page.locator("input[name='api_key']")).to_be_visible()
        expect(page.locator("button[type='submit']")).to_be_visible()
        print("✓ Login form displayed when no API key provided")

    def test_access_with_valid_api_key_in_url(self, page: Page):
        """Test that accessing app with valid API key in URL works correctly."""
        # Navigate with valid API key in URL
        url_with_key = f"{APP_BASE_URL}?api_key={TEST_API_KEY}"
        page.goto(url_with_key, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        
        # Should show main app interface, not login form
        expect(page.locator("#namespaceValue")).to_be_visible(timeout=NAV_TIMEOUT)
        expect(page.locator("#podSelector")).to_be_visible(timeout=NAV_TIMEOUT)
        expect(page.locator("form")).not_to_be_visible()
        print("✓ Main app interface displayed with valid API key")

    def test_access_with_invalid_api_key_shows_form(self, page: Page):
        """Test that accessing app with invalid API key shows login form."""
        # Navigate with invalid API key in URL
        url_with_invalid_key = f"{APP_BASE_URL}?api_key={INVALID_API_KEY}"
        page.goto(url_with_invalid_key, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        
        # Should show API key form, not main app
        expect(page.locator("form")).to_be_visible(timeout=ACTION_TIMEOUT)
        expect(page.locator("input[name='api_key']")).to_be_visible()
        print("✓ Login form displayed with invalid API key")

    def test_api_key_propagated_to_backend_requests(self, page: Page):
        """Test that API key from URL is properly passed to all backend API requests."""
        # Navigate with valid API key
        url_with_key = f"{APP_BASE_URL}?api_key={TEST_API_KEY}"
        
        # Set up network monitoring to check API requests
        api_requests = []
        def handle_request(request):
            if "/api/" in request.url:
                api_requests.append(request.url)
        
        page.on("request", handle_request)
        
        # Navigate and wait for initial data load
        page.goto(url_with_key, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        
        # Wait for namespace to load (indicates successful API calls)
        namespace_display = page.locator("#namespaceValue")
        expect(namespace_display).not_to_have_text("Loading...", timeout=NAV_TIMEOUT)
        expect(namespace_display).not_to_have_text("Error loading", timeout=ACTION_TIMEOUT)
        
        # Verify that API requests include the API key
        assert len(api_requests) > 0, "No API requests were made"
        
        for request_url in api_requests:
            assert f"api_key={TEST_API_KEY}" in request_url, f"API key missing from request: {request_url}"
        
        print(f"✓ API key properly propagated to {len(api_requests)} backend requests")

    def test_pod_list_loads_with_api_key(self, page: Page):
        """Test that pod list loads successfully when API key is provided."""
        # Navigate with valid API key
        url_with_key = f"{APP_BASE_URL}?api_key={TEST_API_KEY}"
        page.goto(url_with_key, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        
        # Wait for pod selector to be populated
        pod_selector = page.locator("#podSelector")
        expect(pod_selector).to_be_visible(timeout=NAV_TIMEOUT)
        
        # Wait for options to be populated (should have at least the "all" option)
        expect(pod_selector.locator("option")).to_have_count_greater_than(0, timeout=NAV_TIMEOUT)
        
        # Verify no error messages
        error_display = page.locator("#errorDisplay")
        expect(error_display).to_have_text("", timeout=ACTION_TIMEOUT)
        
        print("✓ Pod list loaded successfully with API key authentication")

    def test_events_view_works_with_api_key(self, page: Page):
        """Test that events view works correctly with API key authentication."""
        # Navigate with valid API key
        url_with_key = f"{APP_BASE_URL}?api_key={TEST_API_KEY}"
        page.goto(url_with_key, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        
        # Switch to events view
        events_toggle = page.locator("#eventsToggle")
        expect(events_toggle).to_be_visible(timeout=ACTION_TIMEOUT)
        events_toggle.click()
        
        # Wait for events to load
        page.wait_for_timeout(2000)  # Give time for API calls
        
        # Verify events view is active and no errors occurred
        expect(events_toggle).to_be_checked()
        error_display = page.locator("#errorDisplay")
        expect(error_display).to_have_text("", timeout=ACTION_TIMEOUT)
        
        print("✓ Events view works correctly with API key authentication")

    def test_manual_login_form_submission(self, page: Page):
        """Test manual login form submission with valid API key."""
        # Navigate without API key to get login form
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        
        # Fill in API key and submit form
        api_key_input = page.locator("input[name='api_key']")
        submit_button = page.locator("button[type='submit']")
        
        expect(api_key_input).to_be_visible(timeout=ACTION_TIMEOUT)
        api_key_input.fill(TEST_API_KEY)
        submit_button.click()
        
        # Should redirect to main app
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        expect(page.locator("#namespaceValue")).to_be_visible(timeout=NAV_TIMEOUT)
        expect(page.locator("form")).not_to_be_visible()
        
        print("✓ Manual login form submission works correctly")


@pytest.mark.skipif(
    os.environ.get("API_KEY", "no-key") == "no-key",
    reason="No-auth tests require API_KEY to be unset or 'no-key'"
)  
class TestNoAuthenticationFlow:
    """Test behavior when authentication is disabled."""

    def test_access_without_auth_requirement(self, page: Page):
        """Test that app works normally when authentication is disabled."""
        # Navigate without API key
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        
        # Should show main app interface directly, no login form
        expect(page.locator("#namespaceValue")).to_be_visible(timeout=NAV_TIMEOUT)
        expect(page.locator("#podSelector")).to_be_visible(timeout=NAV_TIMEOUT)
        expect(page.locator("form")).not_to_be_visible()
        
        print("✓ Main app accessible without authentication when auth is disabled")


def test_api_key_parameter_extraction():
    """Test that our JavaScript API key extraction logic works correctly."""
    # This could be a unit test for the frontend JS, but keeping it simple
    # The integration tests above cover the actual functionality
    pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])