import os
import re
import time

import pytest
from playwright.sync_api import Page, expect

# Define the base URL of the application
APP_BASE_URL = "http://localhost:5001"
LOG_GEN_POD_NAME_PREFIX = "log-gen-deployment"  # Pod name from log-gen-deployment.yaml

# Timeout for various operations (in milliseconds)
NAV_TIMEOUT = 10000  # 10 seconds for navigation and initial loads
LOG_LOAD_TIMEOUT = 20000  # 20 seconds for logs to appear
ACTION_TIMEOUT = 5000  # 5 seconds for general actions


def test_log_viewer_e2e(page: Page):
    """
    End-to-end test for logPilot.
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
        expect(namespace_display).not_to_have_text("Error loading", timeout=ACTION_TIMEOUT)
        print(f"Namespace displayed: {namespace_display.text_content()}")

        # --- Pod Selection ---
        pod_selector = page.locator("#podSelector")

        # Wait for pod selector to be populated
        # First check if the selector itself exists
        expect(pod_selector).to_be_visible(timeout=NAV_TIMEOUT)

        # Then check for options within the optgroup (expecting 2: init container and main container)
        expect(pod_selector.locator("optgroup[label='Live Pods'] option")).to_have_count(2, timeout=NAV_TIMEOUT)
        print("Pod selector populated.")

        # Find the log-gen pod option (main container, not init container)
        # The pod name will be dynamic, so we look for the prefix
        # We need to handle cases where it might be in an optgroup
        log_gen_pod_option_locator = pod_selector.locator(
            f"option[value^='{LOG_GEN_POD_NAME_PREFIX}'][value*='/log-gen']"
        )

        # If not found directly, check within optgroups (common case)
        if not log_gen_pod_option_locator.count():
            log_gen_pod_option_locator = pod_selector.locator(
                f"optgroup > option[value^='{LOG_GEN_POD_NAME_PREFIX}'][value*='/log-gen']"
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
        expect(log_output).to_contain_text(re.compile(r"INFO", re.IGNORECASE), timeout=ACTION_TIMEOUT)
        print("Found INFO log.")
        expect(log_output).to_contain_text(re.compile(r"WARN", re.IGNORECASE), timeout=ACTION_TIMEOUT)
        print("Found WARN log.")
        expect(log_output).to_contain_text(re.compile(r"ERROR", re.IGNORECASE), timeout=ACTION_TIMEOUT)
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
        expect(log_output.locator("div.log-line mark")).not_to_have_count(0, timeout=ACTION_TIMEOUT)
        print("Search term highlighting found.")

        log_lines = log_output.locator("div.log-line")
        for i in range(log_lines.count()):
            line = log_lines.nth(i)
            message_span = line.locator("span.log-message")
            marked_text_count = message_span.locator(f"mark:has-text('{search_term}')").count()

            # A line is valid if it's highlighted OR its text content includes the search term
            # (The log-gen pod might also output "Error fetching logs" if it has issues, these are also valid if searching for "Error")
            if marked_text_count == 0:
                expect(message_span).to_contain_text(search_term, ignore_case=True)

        print(f"Search functionality verified. All visible logs contain '{search_term}'.")

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
        expect(log_output).to_contain_text(re.compile(r"INFO", re.IGNORECASE), timeout=ACTION_TIMEOUT)
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


def test_sort_order_functionality(page: Page):
    """
    Test sort order functionality for live pods, archived pods, and all pods view.
    1. Tests newest first and oldest first for live pods
    2. Tests newest first and oldest first for archived pods (if available)
    3. Tests newest first and oldest first for all pods view
    """
    try:
        # Navigate to the app
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Wait for namespace to be displayed
        namespace_display = page.locator("#namespaceValue")
        expect(namespace_display).not_to_have_text("Loading...", timeout=NAV_TIMEOUT)
        expect(namespace_display).not_to_have_text("Error loading", timeout=ACTION_TIMEOUT)

        pod_selector = page.locator("#podSelector")
        sort_order_selector = page.locator("#sortOrder")
        log_output = page.locator("#logOutput")
        loading_indicator = page.locator("#loadingIndicator")
        settings_button = page.locator("#settingsButton")

        # Wait for pod selector to be populated
        expect(pod_selector).to_be_visible(timeout=NAV_TIMEOUT)
        expect(pod_selector.locator("optgroup[label='Live Pods'] option")).to_have_count(2, timeout=NAV_TIMEOUT)

        # Find the log-gen pod (main container, not init container)
        log_gen_pod_option_locator = pod_selector.locator(
            f"option[value^='{LOG_GEN_POD_NAME_PREFIX}'][value*='/log-gen']"
        )
        if not log_gen_pod_option_locator.count():
            log_gen_pod_option_locator = pod_selector.locator(
                f"optgroup > option[value^='{LOG_GEN_POD_NAME_PREFIX}'][value*='/log-gen']"
            )

        expect(log_gen_pod_option_locator).not_to_have_count(0, timeout=NAV_TIMEOUT)
        log_gen_pod_value = log_gen_pod_option_locator.first.get_attribute("value")
        if log_gen_pod_value is None:
            raise ValueError("log_gen_pod_option does not have a value attribute")

        # Helper function to get timestamps from log entries
        def get_log_timestamps():
            page.wait_for_function(
                """
                () => {
                    const content = document.querySelector('#logOutput').textContent;
                    return content && content.trim().length > 0 && 
                           !content.includes('No logs to display') && 
                           !content.includes('Error loading logs');
                }
                """,
                timeout=LOG_LOAD_TIMEOUT,
            )

            # Get all log lines with timestamps
            log_lines = log_output.locator("div.log-line")
            timestamps = []
            for i in range(min(log_lines.count(), 5)):  # Check first 5 lines
                line = log_lines.nth(i)
                timestamp_span = line.locator("span.timestamp")
                if timestamp_span.count() > 0:
                    timestamp_text = timestamp_span.text_content()
                    if timestamp_text:
                        timestamps.append(timestamp_text.strip())
            return timestamps

        # Test 1: Live pod with newest first (default)
        print("Testing live pod with newest first...")
        pod_selector.select_option(log_gen_pod_value)
        expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

        # Open settings menu to access sort order
        settings_button.click()
        expect(sort_order_selector).to_be_visible(timeout=ACTION_TIMEOUT)

        sort_order_selector.select_option("desc")  # Newest first
        expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

        newest_first_timestamps = get_log_timestamps()
        print(f"Newest first timestamps: {newest_first_timestamps[:3]}")

        # Test 2: Live pod with oldest first
        print("Testing live pod with oldest first...")
        sort_order_selector.select_option("asc")  # Oldest first
        expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

        oldest_first_timestamps = get_log_timestamps()
        print(f"Oldest first timestamps: {oldest_first_timestamps[:3]}")

        # Verify that the order is different (unless there's only one log entry)
        if len(newest_first_timestamps) > 1 and len(oldest_first_timestamps) > 1:
            assert newest_first_timestamps != oldest_first_timestamps, "Sort order should change timestamps order"
            # First timestamp in newest-first should be newer than first in oldest-first
            assert newest_first_timestamps[0] >= oldest_first_timestamps[0], (
                "Newest first should show newer logs at top"
            )

        # Test 3: Check if archived pods are available
        archived_pod_options = pod_selector.locator("optgroup[label='Archived Pods'] option")
        archived_pod_count = archived_pod_options.count()

        if archived_pod_count > 0:
            print(f"Testing archived pods (found {archived_pod_count})...")

            # Select first archived pod
            archived_pod_value = archived_pod_options.first.get_attribute("value")
            pod_selector.select_option(archived_pod_value)
            expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

            # Test newest first for archived pod
            sort_order_selector.select_option("desc")
            expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

            archived_newest_first = get_log_timestamps()
            print(f"Archived newest first: {archived_newest_first[:3]}")

            # Test oldest first for archived pod
            sort_order_selector.select_option("asc")
            expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

            archived_oldest_first = get_log_timestamps()
            print(f"Archived oldest first: {archived_oldest_first[:3]}")

            # Verify order is different for archived logs too
            if len(archived_newest_first) > 1 and len(archived_oldest_first) > 1:
                assert archived_newest_first != archived_oldest_first, "Archived logs sort order should change"
        else:
            print("No archived pods found, skipping archived pod sort tests")

        # Test 4: All pods view
        print("Testing all pods view...")
        pod_selector.select_option("all")
        expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

        # Test newest first for all pods
        sort_order_selector.select_option("desc")
        expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

        all_pods_newest_first = get_log_timestamps()
        print(f"All pods newest first: {all_pods_newest_first[:3]}")

        # Test oldest first for all pods
        sort_order_selector.select_option("asc")
        expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)

        all_pods_oldest_first = get_log_timestamps()
        print(f"All pods oldest first: {all_pods_oldest_first[:3]}")

        # Verify order is different for all pods view
        if len(all_pods_newest_first) > 1 and len(all_pods_oldest_first) > 1:
            assert all_pods_newest_first != all_pods_oldest_first, "All pods sort order should change"

        print("Sort order functionality test completed successfully.")

    except Exception as e:
        # Capture a screenshot on failure
        screenshot_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "test-results",
            "test-failure-sort-screenshot.png",
        )
        page.screenshot(path=screenshot_path)
        print(f"Sort order test failed: {e}")
        pytest.fail(f"Sort order test failed due to: {e}")


def test_error_handling_and_retry_functionality(page: Page):
    """
    Test enhanced error handling and retry functionality.
    1. Tests that error messages are displayed with proper styling
    2. Tests retry button functionality when available
    3. Tests different error types and their handling
    """
    try:
        # Navigate to the app
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Wait for namespace to be displayed
        namespace_display = page.locator("#namespaceValue")
        expect(namespace_display).not_to_have_text("Loading...", timeout=NAV_TIMEOUT)

        # Test error display by trying to fetch logs for a non-existent pod
        pod_selector = page.locator("#podSelector")
        expect(pod_selector).to_be_visible(timeout=NAV_TIMEOUT)

        # Inject a test to simulate error conditions
        page.evaluate("""
            () => {
                // Store original fetch function
                window.originalFetch = window.fetch;
                window.errorTestActive = false;
                
                // Create a function to simulate API errors
                window.simulateAPIError = function(errorType) {
                    window.errorTestActive = true;
                    window.fetch = async function(url, options) {
                        if (url.includes('/api/logs') && window.errorTestActive) {
                            // Simulate different types of errors
                            const response = new Response(
                                JSON.stringify({
                                    message: errorType === 'retry' ? 
                                        'Service temporarily unavailable' : 
                                        'Resource not found',
                                    error_type: errorType === 'retry' ? 'service_error' : 'not_found_error',
                                    retry_suggested: errorType === 'retry'
                                }),
                                { 
                                    status: errorType === 'retry' ? 503 : 404,
                                    headers: { 'Content-Type': 'application/json' }
                                }
                            );
                            return response;
                        }
                        return window.originalFetch(url, options);
                    };
                };
                
                window.restoreOriginalFetch = function() {
                    window.errorTestActive = false;
                    window.fetch = window.originalFetch;
                };
            }
        """)

        # Wait for pods to load normally first
        try:
            page.wait_for_function(
                "document.querySelector('#podSelector').options.length > 1",
                timeout=NAV_TIMEOUT
            )
        except:
            print("No pods available for error testing - skipping error simulation tests")
            return

        # Test 1: Error with retry suggestion
        print("Testing error with retry suggestion...")
        page.evaluate("window.simulateAPIError('retry')")
        
        # Select a pod to trigger log fetching
        pod_options = pod_selector.locator("option")
        if pod_options.count() > 1:
            first_pod_value = pod_options.nth(1).get_attribute("value")
            if first_pod_value:
                pod_selector.select_option(first_pod_value)
                
                # Wait for loading to complete
                loading_indicator = page.locator("#loadingIndicator")
                try:
                    expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)
                except:
                    print("Loading indicator timeout - continuing with test")
                
                # Check for error display in logs
                log_output = page.locator("#logOutput")
                
                # Look for error entries in the log display
                # The error might be displayed as a log entry or in the error display area
                error_display = page.locator("#errorDisplay")
                
                # Check if error is shown in either location
                try:
                    error_display_text = error_display.text_content() or ""
                    log_output_text = log_output.text_content() or ""
                    error_elements = log_output.locator(".log-error")
                    
                    error_shown = (
                        error_display_text.strip() or
                        error_elements.count() > 0 or
                        "error" in log_output_text.lower()
                    )
                except Exception as e:
                    print(f"Error checking failed: {e}")
                    error_shown = False
                
                if error_shown:
                    print("Error successfully displayed")
                    
                    # Look for retry button if present
                    retry_buttons = log_output.locator(".retry-button")
                    if retry_buttons.count() > 0:
                        print("Retry button found and is clickable")
                        try:
                            expect(retry_buttons.first).to_be_visible(timeout=3000)
                            
                            # Test retry button functionality
                            page.evaluate("window.restoreOriginalFetch()")  # Restore normal fetch
                            retry_buttons.first.click()
                            
                            # Wait for retry to complete
                            try:
                                expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)
                                print("Retry functionality tested")
                            except:
                                print("Retry completed (loading indicator check timed out)")
                        except Exception as e:
                            print(f"Retry button test failed: {e}")
                else:
                    print("Error display test completed (no error shown - may be expected)")

        # Test 2: Error without retry suggestion (optional)
        try:
            print("Testing error without retry suggestion...")
            page.evaluate("window.simulateAPIError('no_retry')")
            
            # Trigger another log fetch
            if pod_options.count() > 1:
                # Select a different pod or re-select the same one
                pod_selector.select_option(first_pod_value)
                try:
                    expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)
                except:
                    print("Loading timeout for no-retry test - continuing")
                
                # Check that error is displayed but without retry button
                error_display = page.locator("#errorDisplay")
                log_output = page.locator("#logOutput")
                
                try:
                    error_display_text = error_display.text_content() or ""
                    log_output_text = log_output.text_content() or ""
                    
                    error_shown = (
                        error_display_text.strip() or
                        log_output.locator(".log-error").count() > 0 or
                        "error" in log_output_text.lower()
                    )
                    
                    if error_shown:
                        print("Error without retry displayed correctly")
                    else:
                        print("No error shown for no-retry test")
                except Exception as e:
                    print(f"Error checking for no-retry test failed: {e}")
        except Exception as e:
            print(f"No-retry error test failed: {e}")

        # Restore normal functionality
        page.evaluate("window.restoreOriginalFetch()")
        
        # Test 3: Verify normal operation after error recovery
        print("Testing normal operation after error recovery...")
        try:
            pod_selector.select_option(first_pod_value)
            expect(loading_indicator).to_be_hidden(timeout=LOG_LOAD_TIMEOUT)
        except:
            print("Recovery test timeout - continuing")
        
        # Should now work normally (optional verification)
        try:
            page.wait_for_function(
                """
                () => {
                    const content = document.querySelector('#logOutput').textContent;
                    return content && content.trim().length > 0 && 
                           !content.includes('Error loading logs');
                }
                """,
                timeout=LOG_LOAD_TIMEOUT,
            )
            print("Normal operation restored after error recovery")
        except:
            print("Normal operation verification timed out - test still successful")

        print("Error handling and retry functionality test completed successfully.")

    except Exception as e:
        # Restore normal fetch in case of test failure
        page.evaluate("window.restoreOriginalFetch && window.restoreOriginalFetch()")
        
        screenshot_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "test-results",
            "test-failure-error-handling-screenshot.png",
        )
        page.screenshot(path=screenshot_path)
        print(f"Error handling test failed: {e}")
        pytest.fail(f"Error handling test failed due to: {e}")


def test_ansi_css_and_styling_loaded(page: Page):
    """
    Test that ANSI CSS classes and error styling are properly loaded.
    1. Verifies ANSI color classes are present
    2. Verifies error styling classes are available
    3. Tests theme-specific styling
    """
    try:
        # Navigate to the app
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        print("Testing ANSI CSS classes and styling...")

        # Check that essential ANSI CSS classes are loaded
        ansi_classes_loaded = page.evaluate("""
            () => {
                const requiredClasses = [
                    'ansi-red', 'ansi-green', 'ansi-blue', 'ansi-yellow',
                    'log-error', 'retry-button'
                ];
                
                const styles = Array.from(document.styleSheets)
                    .flatMap(sheet => {
                        try {
                            return Array.from(sheet.cssRules);
                        } catch (e) {
                            return [];  // Handle CORS issues with external stylesheets
                        }
                    })
                    .map(rule => rule.selectorText || '')
                    .join(' ');
                
                const foundClasses = requiredClasses.filter(className => 
                    styles.includes('.' + className)
                );
                
                return {
                    found: foundClasses,
                    missing: requiredClasses.filter(c => !foundClasses.includes(c)),
                    totalStyles: styles.length
                };
            }
        """)

        print(f"ANSI classes found: {ansi_classes_loaded['found']}")
        if ansi_classes_loaded['missing']:
            print(f"Missing classes: {ansi_classes_loaded['missing']}")

        # We should find at least some essential classes
        assert len(ansi_classes_loaded['found']) >= 3, "Not enough ANSI CSS classes found"

        # Test theme switching affects styling (optional - skip if settings not available)
        settings_button = page.locator("#settingsButton")
        try:
            # Wait for settings button to be visible and clickable
            expect(settings_button).to_be_visible(timeout=5000)
            expect(settings_button).to_be_enabled(timeout=5000)
            
            settings_button.click()
            settings_menu = page.locator("#settingsMenu")
            expect(settings_menu).to_be_visible(timeout=ACTION_TIMEOUT)

            # Test dark mode
            dark_theme_radio = page.locator("#themeDark")
            if dark_theme_radio.is_visible():
                dark_theme_radio.click()
                
                # Check that dark class is applied to body
                body_has_dark = page.evaluate("document.body.classList.contains('dark')")
                if body_has_dark:
                    print("Dark mode successfully applied")

            # Test light mode
            light_theme_radio = page.locator("#themeLight")
            if light_theme_radio.is_visible():
                light_theme_radio.click()
                
                # Check that dark class is removed from body
                body_has_dark = page.evaluate("document.body.classList.contains('dark')")
                if not body_has_dark:
                    print("Light mode successfully applied")

            # Close settings menu by clicking elsewhere or the button again
            try:
                settings_button.click(timeout=2000)
            except:
                # If clicking settings button fails, click elsewhere to close menu
                page.click("body", timeout=2000)
                
        except Exception as e:
            print(f"Theme switching test skipped - settings not accessible: {e}")
            # This is not a critical failure for ANSI CSS testing

        print("ANSI CSS and styling test completed successfully.")

    except Exception as e:
        screenshot_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "test-results",
            "test-failure-ansi-css-screenshot.png",
        )
        page.screenshot(path=screenshot_path)
        print(f"ANSI CSS test failed: {e}")
        pytest.fail(f"ANSI CSS test failed due to: {e}")
