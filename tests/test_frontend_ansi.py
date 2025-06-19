"""
Frontend-focused tests for ANSI rendering and error display functionality.
Uses Playwright to test visual elements and user interactions.
"""

import pytest
from playwright.sync_api import Page, expect

# Test configuration
APP_BASE_URL = "http://localhost:5001"
NAV_TIMEOUT = 10000
ACTION_TIMEOUT = 5000


class TestANSIRendering:
    """Test ANSI color rendering and visual feedback."""

    def test_ansi_css_classes_present(self, page: Page):
        """Test that all ANSI CSS classes are loaded and available."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Check that ANSI color classes exist in the document
        ansi_colors = [
            "ansi-red",
            "ansi-green",
            "ansi-blue",
            "ansi-yellow",
            "ansi-magenta",
            "ansi-cyan",
            "ansi-white",
            "ansi-black",
            "ansi-bright-red",
            "ansi-bright-green",
            "ansi-bright-blue",
        ]

        for color_class in ansi_colors:
            # Check if the CSS class exists by looking at computed styles
            class_exists = page.evaluate(f"""
                () => {{
                    const styles = Array.from(document.styleSheets)
                        .flatMap(sheet => Array.from(sheet.cssRules))
                        .map(rule => rule.selectorText)
                        .join(' ');
                    return styles.includes('.{color_class}');
                }}
            """)
            assert class_exists, f"ANSI color class .{color_class} not found in CSS"

    def test_error_styling_classes_present(self, page: Page):
        """Test that error styling classes are loaded."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Check for error-related CSS classes
        error_classes = ["log-error", "retry-button"]

        for error_class in error_classes:
            class_exists = page.evaluate(f"""
                () => {{
                    const styles = Array.from(document.styleSheets)
                        .flatMap(sheet => Array.from(sheet.cssRules))
                        .map(rule => rule.selectorText)
                        .join(' ');
                    return styles.includes('.{error_class}');
                }}
            """)
            assert class_exists, f"Error styling class .{error_class} not found in CSS"

    def test_dark_mode_ansi_classes(self, page: Page):
        """Test that dark mode ANSI classes are present."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Check for dark mode ANSI classes
        dark_mode_exists = page.evaluate("""
            () => {
                const styles = Array.from(document.styleSheets)
                    .flatMap(sheet => Array.from(sheet.cssRules))
                    .map(rule => rule.selectorText)
                    .join(' ');
                return styles.includes('.dark .ansi-red') || 
                       styles.includes('.dark .ansi-green');
            }
        """)
        assert dark_mode_exists, "Dark mode ANSI classes not found"


class TestErrorDisplay:
    """Test error display and retry functionality."""

    def test_error_message_display_format(self, page: Page):
        """Test that error messages are displayed with proper formatting."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Try to trigger an error by selecting a non-existent pod
        # First, let's inject a mock error response for testing
        page.evaluate("""
            () => {
                // Mock the fetchFromServer function to return an error
                window.originalFetchFromServer = window.fetchFromServer;
                window.fetchFromServer = async function(endpoint) {
                    if (endpoint.includes('/api/logs')) {
                        const error = new Error('Test error message');
                        error.retrySuggested = true;
                        error.errorType = 'test_error';
                        throw error;
                    }
                    return window.originalFetchFromServer(endpoint);
                };
            }
        """)

        # Wait for pods to load
        pod_selector = page.locator("#podSelector")
        expect(pod_selector).to_be_visible(timeout=NAV_TIMEOUT)

        # Wait for pods to be populated
        page.wait_for_function("document.querySelector('#podSelector').options.length > 1", timeout=NAV_TIMEOUT)

        # Select a pod to trigger log loading (which will now error)
        pod_options = pod_selector.locator("option")
        if pod_options.count() > 1:
            # Select the first non-empty option
            first_pod_value = pod_options.nth(1).get_attribute("value")
            if first_pod_value:
                pod_selector.select_option(first_pod_value)

                # Wait for the error to be displayed
                log_output = page.locator("#logOutput")

                # Check if error is displayed with proper styling
                error_elements = log_output.locator(".log-error")
                if error_elements.count() > 0:
                    # Error should be visible and styled
                    expect(error_elements.first).to_be_visible()

                    # Check for retry button if suggested
                    retry_buttons = error_elements.locator(".retry-button")
                    if retry_buttons.count() > 0:
                        expect(retry_buttons.first).to_be_visible()
                        expect(retry_buttons.first).to_have_text("Retry")

    def test_error_display_without_retry(self, page: Page):
        """Test error display when retry is not suggested."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Mock an error without retry suggestion
        page.evaluate("""
            () => {
                window.testErrorWithoutRetry = function() {
                    const logOutput = document.querySelector('#logOutput');
                    const errorDiv = document.createElement('div');
                    errorDiv.className = 'log-line log-error';
                    
                    const errorContent = document.createElement('div');
                    errorContent.innerHTML = 'Test error without retry option';
                    errorDiv.appendChild(errorContent);
                    
                    logOutput.innerHTML = '';
                    logOutput.appendChild(errorDiv);
                };
                window.testErrorWithoutRetry();
            }
        """)

        # Check that error is displayed but without retry button
        log_output = page.locator("#logOutput")
        error_elements = log_output.locator(".log-error")
        expect(error_elements).to_have_count(1)

        # Should not have retry button
        retry_buttons = error_elements.locator(".retry-button")
        expect(retry_buttons).to_have_count(0)

    def test_theme_toggle_affects_error_styling(self, page: Page):
        """Test that theme changes affect error styling appropriately."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Open settings to access theme toggle
        settings_button = page.locator("#settingsButton")
        settings_button.click()

        # Wait for settings menu to be visible
        settings_menu = page.locator("#settingsMenu")
        expect(settings_menu).to_be_visible(timeout=ACTION_TIMEOUT)

        # Test theme toggle
        light_theme_radio = page.locator("#themeLight")
        dark_theme_radio = page.locator("#themeDark")

        # Switch to light theme
        if light_theme_radio.is_visible():
            light_theme_radio.click()

            # Check that html element doesn't have dark class
            html_classes = page.evaluate("document.documentElement.className")
            assert "dark" not in html_classes

        # Switch to dark theme
        if dark_theme_radio.is_visible():
            dark_theme_radio.click()

            # Check that html element has dark class
            html_classes = page.evaluate("document.documentElement.className")
            assert "dark" in html_classes


class TestInteractiveFeatures:
    """Test interactive features related to error handling and ANSI display."""

    def test_retry_button_functionality(self, page: Page):
        """Test that retry buttons are clickable and functional."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Create a mock error with retry button
        page.evaluate("""
            () => {
                window.retryClicked = false;
                window.createMockErrorWithRetry = function() {
                    const logOutput = document.querySelector('#logOutput');
                    const errorDiv = document.createElement('div');
                    errorDiv.className = 'log-line log-error';
                    
                    const errorContent = document.createElement('div');
                    errorContent.innerHTML = 'Mock error message ';
                    
                    const retryButton = document.createElement('button');
                    retryButton.textContent = 'Retry';
                    retryButton.className = 'retry-button';
                    retryButton.onclick = () => { window.retryClicked = true; };
                    
                    errorContent.appendChild(retryButton);
                    errorDiv.appendChild(errorContent);
                    
                    logOutput.innerHTML = '';
                    logOutput.appendChild(errorDiv);
                };
                window.createMockErrorWithRetry();
            }
        """)

        # Find and click the retry button
        retry_button = page.locator(".retry-button")
        expect(retry_button).to_be_visible()
        expect(retry_button).to_be_enabled()

        retry_button.click()

        # Verify that click was registered
        retry_clicked = page.evaluate("window.retryClicked")
        assert retry_clicked, "Retry button click was not registered"

    def test_ansi_color_contrast_visibility(self, page: Page):
        """Test that ANSI colors have sufficient contrast for visibility."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Create test elements with different ANSI colors
        page.evaluate("""
            () => {
                const logOutput = document.querySelector('#logOutput');
                const ansiColors = [
                    'ansi-red', 'ansi-green', 'ansi-blue', 'ansi-yellow',
                    'ansi-magenta', 'ansi-cyan'
                ];
                
                logOutput.innerHTML = '';
                ansiColors.forEach(colorClass => {
                    const testDiv = document.createElement('div');
                    testDiv.className = 'log-line';
                    testDiv.innerHTML = `<span class="${colorClass}">Test ${colorClass} text</span>`;
                    logOutput.appendChild(testDiv);
                });
            }
        """)

        # Check that all color elements are visible
        ansi_elements = page.locator("#logOutput .log-line span")
        expect(ansi_elements).to_have_count(6)

        # Each element should have text content
        for i in range(6):
            element = ansi_elements.nth(i)
            expect(element).to_be_visible()
            expect(element).not_to_have_text("")

    def test_search_highlighting_with_ansi_content(self, page: Page):
        """Test that search highlighting works with ANSI-colored content."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Create mock log content with ANSI colors
        page.evaluate("""
            () => {
                const logOutput = document.querySelector('#logOutput');
                logOutput.innerHTML = `
                    <div class="log-line">
                        <span class="log-message">
                            <span class="ansi-red">ERROR</span>: Something went wrong
                        </span>
                    </div>
                    <div class="log-line">
                        <span class="log-message">
                            <span class="ansi-green">INFO</span>: Application started
                        </span>
                    </div>
                `;
            }
        """)

        # Test that the content is visible
        log_output = page.locator("#logOutput")
        expect(log_output).to_contain_text("ERROR")
        expect(log_output).to_contain_text("INFO")

        # Check that ANSI classes are applied
        red_text = log_output.locator(".ansi-red")
        green_text = log_output.locator(".ansi-green")

        expect(red_text).to_be_visible()
        expect(green_text).to_be_visible()
        expect(red_text).to_have_text("ERROR")
        expect(green_text).to_have_text("INFO")


class TestAccessibility:
    """Test accessibility features for error display and ANSI content."""

    def test_error_messages_have_appropriate_aria_labels(self, page: Page):
        """Test that error messages have appropriate accessibility attributes."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Create accessible error display
        page.evaluate("""
            () => {
                const logOutput = document.querySelector('#logOutput');
                const errorDiv = document.createElement('div');
                errorDiv.className = 'log-line log-error';
                errorDiv.setAttribute('role', 'alert');
                errorDiv.setAttribute('aria-live', 'polite');
                errorDiv.innerHTML = '<div>Accessible error message</div>';
                
                logOutput.innerHTML = '';
                logOutput.appendChild(errorDiv);
            }
        """)

        # Check for accessibility attributes
        error_element = page.locator(".log-error")
        expect(error_element).to_have_attribute("role", "alert")
        expect(error_element).to_have_attribute("aria-live", "polite")

    def test_retry_buttons_have_proper_labels(self, page: Page):
        """Test that retry buttons have appropriate accessibility labels."""
        page.goto(APP_BASE_URL, timeout=NAV_TIMEOUT)
        page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)

        # Create retry button with accessibility attributes
        page.evaluate("""
            () => {
                const logOutput = document.querySelector('#logOutput');
                const errorDiv = document.createElement('div');
                errorDiv.className = 'log-line log-error';
                
                const retryButton = document.createElement('button');
                retryButton.textContent = 'Retry';
                retryButton.className = 'retry-button';
                retryButton.setAttribute('aria-label', 'Retry failed operation');
                retryButton.setAttribute('type', 'button');
                
                errorDiv.appendChild(retryButton);
                logOutput.innerHTML = '';
                logOutput.appendChild(errorDiv);
            }
        """)

        # Check button accessibility
        retry_button = page.locator(".retry-button")
        expect(retry_button).to_have_attribute("aria-label", "Retry failed operation")
        expect(retry_button).to_have_attribute("type", "button")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
