import re
import pytest
from playwright.sync_api import Page, expect
import time
import os

# Define the base URL of the application
APP_BASE_URL = "http://localhost:5001"
LOG_GEN_POD_NAME_PREFIX = "log-gen-deployment"  # Pod name from log-gen-deployment.yaml

# Timeout for various operations (in milliseconds)
NAV_TIMEOUT = 10000  # 10 seconds for navigation and initial loads
LOG_LOAD_TIMEOUT = 20000  # 20 seconds for logs to appear
ACTION_TIMEOUT = 5000  # 5 seconds for general actions


def test_log_viewer_e2e(page: Page):
    """
    End-to-end test for the Kubernetes Log Viewer.
    1. Navigates to the app.
    2. Waits for pod list to load and finds the log-gen pod.
    3. Selects the log-gen pod.
    4. Waits for logs to appear.
    5. Verifies that logs contain expected patterns (INFO, WARN, ERROR).
    6. Tests search functionality.
    """
    try:
        # 1. Navigate to the app
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Wait for namespace to be displayed (indicates initial data load)
        namespace_display = page.locator("#namespaceValue")
        expect(namespace_display).not_to_have_text("Loading...", timeout=NAV_TIMEOUT)
        expect(namespace_display).not_to_have_text(
            "Error loading", timeout=ACTION_TIMEOUT
        )
        print(f"Namespace displayed: {namespace_display.text_content()}")

        # --- Pod Selection ---
        pod_selector = page.locator("#podSelector")

        # Wait for pod selector to be populated
        # First check if the selector itself exists
        expect(pod_selector).to_be_visible(timeout=NAV_TIMEOUT)

        # Then check for options within the optgroup
        expect(
            pod_selector.locator("optgroup[label='Live Pods'] option")
        ).to_have_count(1, timeout=NAV_TIMEOUT)
        print("Pod selector populated.")

        # Find the log-gen pod option
        # The pod name will be dynamic, so we look for the prefix
        # We need to handle cases where it might be in an optgroup
        log_gen_pod_option_locator = pod_selector.locator(
            f"option[value^='{LOG_GEN_POD_NAME_PREFIX}']"
        )

        # If not found directly, check within optgroups (common case)
        if not log_gen_pod_option_locator.count():
            log_gen_pod_option_locator = pod_selector.locator(
                f"optgroup > option[value^='{LOG_GEN_POD_NAME_PREFIX}']"
            )

        expect(log_gen_pod_option_locator).not_to_have_count(0, timeout=NAV_TIMEOUT)

        log_gen_pod_value = log_gen_pod_option_locator.first.get_attribute("value")
        if log_gen_pod_value is None:
            raise ValueError("log_gen_pod_option does not have a value attribute")

        print(f"Found log-gen pod: {log_gen_pod_value}")

        # Select the log-gen pod
        pod_selector.select_option(log_gen_pod_value)
        print(f"Selected pod: {log_gen_pod_value}")

        # Wait for loading indicator to disappear after selection
        loading_indicator = page.locator("#loadingIndicator")
        expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)
        print("Loading indicator hidden after pod selection.")

        # --- Log Verification ---
        log_output = page.locator("#logOutput")

        # Wait for log output to contain some text
        # Use a JavaScript function to check for non-empty, non-error message content
        page.wait_for_function(
            """
            () => {
                const content = document.querySelector('#logOutput').textContent;
                if (!content) return false;
                const isNotEmpty = content.trim().length > 0;
                const isNotPlaceholder = !content.includes('No logs to display') && !content.includes('Error loading logs');
                return isNotEmpty && isNotPlaceholder;
            }
        """,
            timeout=LOG_LOAD_TIMEOUT,
        )
        print("Initial logs loaded.")

        # Verify specific log patterns from log-gen.py
        # The log-gen script cycles through INFO, WARN, ERROR
        # Give it a few seconds to emit a few log lines
        time.sleep(5)  # Wait for a few log lines to be generated and fetched

        # Re-fetch logs after waiting to ensure we have fresh data
        # This can be done by simply re-evaluating the log_output or, if the app has a refresh, using it.
        # For simplicity here, we assume the logs are continuously updating or a new fetch occurred.
        # If a manual refresh button existed and was needed:
        # page.locator("#refreshLogsButton").click() # Assuming such a button exists
        # expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

        # Check for INFO, WARN, ERROR messages (case-insensitive check on the message content)
        # The log-gen script produces "[INFO] This is a test log", "[WARN] This is a test log", etc.
        # The UI colors these, so we look for the text and can also check for the color classes

        # Regex to find styled log messages (e.g., <span class="...text-red...">...ERROR...</span>)
        # This is a simplified check for the text content within the log lines.
        expect(log_output).to_contain_text(
            re.compile(r"INFO", re.IGNORECASE), timeout=ACTION_TIMEOUT
        )
        print("Found INFO log.")
        expect(log_output).to_contain_text(
            re.compile(r"WARN", re.IGNORECASE), timeout=ACTION_TIMEOUT
        )
        print("Found WARN log.")
        expect(log_output).to_contain_text(
            re.compile(r"ERROR", re.IGNORECASE), timeout=ACTION_TIMEOUT
        )
        print("Found ERROR log.")

        # --- Search Functionality Test ---
        search_box = page.locator("#searchBox")
        search_term = "ERROR"

        print(f"Testing search for: {search_term}")
        search_box.fill(search_term)
        search_box.press("Enter")

        expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)
        print("Loading indicator hidden after search.")

        # Wait for search results to update
        page.wait_for_function(
            """
            () => {
                const content = document.querySelector('#logOutput').textContent;
                if (!content) return false;
                const isNotEmpty = content.trim().length > 0;
                const isNotPlaceholder = !content.includes('No logs to display') && !content.includes('Error loading logs');
                return isNotEmpty && isNotPlaceholder;
            }
        """,
            timeout=LOG_LOAD_TIMEOUT,
        )
        print("Logs updated after search.")

        # Verify that only logs containing "ERROR" (and highlighted) are shown
        # All log lines should now contain the search term (or be part of the highlighted message)
        # This checks if all visible log *messages* (not timestamps or pod names) contain "ERROR"
        # The highlighting is done with <mark> tags

        # Wait for at least one marked log line
        expect(log_output.locator("div.log-line mark")).not_to_have_count(
            0, timeout=ACTION_TIMEOUT
        )
        print("Search term highlighting found.")

        log_lines = log_output.locator("div.log-line")
        for i in range(log_lines.count()):
            line = log_lines.nth(i)
            message_span = line.locator("span.log-message")
            marked_text_count = message_span.locator(
                f"mark:has-text('{search_term}')"
            ).count()

            # A line is valid if it's highlighted OR its text content includes the search term
            # (The log-gen pod might also output "Error fetching logs" if it has issues, these are also valid if searching for "Error")
            if marked_text_count == 0:
                expect(message_span).to_contain_text(search_term, ignore_case=True)

        print(
            f"Search functionality verified. All visible logs contain '{search_term}'."
        )

        # Clear search
        clear_search_button = page.locator("#clearSearch")
        clear_search_button.click()
        expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)
        expect(search_box).to_have_value("", timeout=ACTION_TIMEOUT)
        print("Search cleared.")

        # Verify logs are back to normal (e.g., INFO/WARN should reappear if previously filtered out)
        page.wait_for_function(
            """
            () => {
                const content = document.querySelector('#logOutput').textContent;
                if (!content) return false;
                const isNotEmpty = content.trim().length > 0;
                const isNotPlaceholder = !content.includes('No logs to display') && !content.includes('Error loading logs');
                return isNotEmpty && isNotPlaceholder;
            }
        """,
            timeout=LOG_LOAD_TIMEOUT,
        )
        expect(log_output).to_contain_text(
            re.compile(r"INFO", re.IGNORECASE), timeout=ACTION_TIMEOUT
        )
        print("INFO logs visible again after clearing search.")

        print("Playwright test completed successfully.")

    except Exception as e:
        # Capture a screenshot on failure
        screenshot_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "test-results",
            "test-failure-screenshot.png",
        )
        page.screenshot(path=screenshot_path)
        print(f"Test failed: {e}")
        pytest.fail(f"Test failed due to: {e}")
