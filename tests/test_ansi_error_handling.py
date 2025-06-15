"""
Unit tests for ANSI text processing and error handling functionality.
Tests the core functions added for ANSI escape sequence handling,
log message sanitization, and enhanced error handling.
"""

import json
import pytest
from unittest.mock import Mock
from kubernetes.client.rest import ApiException

# Import the functions we want to test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import main module and extract functions
try:
    import main
    strip_ansi_codes = main.strip_ansi_codes
    convert_ansi_to_html = main.convert_ansi_to_html
    sanitize_log_message = main.sanitize_log_message
    parse_log_line = main.parse_log_line
    format_k8s_error = main.format_k8s_error
    create_error_log_entry = main.create_error_log_entry
    retry_k8s_operation = main.retry_k8s_operation
except ImportError as e:
    pytest.skip(f"Could not import main module: {e}", allow_module_level=True)


class TestANSIProcessing:
    """Test ANSI escape sequence processing functions."""

    def test_strip_ansi_codes_basic_colors(self):
        """Test stripping basic ANSI color codes."""
        # Red text
        input_text = "\x1b[31mRed text\x1b[0m"
        expected = "Red text"
        assert strip_ansi_codes(input_text) == expected

        # Green background
        input_text = "\x1b[42mGreen background\x1b[0m"
        expected = "Green background"
        assert strip_ansi_codes(input_text) == expected

    def test_strip_ansi_codes_complex_sequences(self):
        """Test stripping complex ANSI sequences."""
        # Multiple colors and styles
        input_text = "\x1b[1;31;42mBold red text on green background\x1b[0m"
        expected = "Bold red text on green background"
        assert strip_ansi_codes(input_text) == expected

        # Cursor movement sequences
        input_text = "\x1b[2J\x1b[HClear screen and home\x1b[K"
        expected = "Clear screen and home"
        assert strip_ansi_codes(input_text) == expected

    def test_strip_ansi_codes_no_ansi(self):
        """Test that normal text is unchanged."""
        input_text = "Normal text without ANSI codes"
        assert strip_ansi_codes(input_text) == input_text

    def test_strip_ansi_codes_empty_string(self):
        """Test empty string handling."""
        assert strip_ansi_codes("") == ""
        assert strip_ansi_codes(None) is None

    def test_convert_ansi_to_html_basic_colors(self):
        """Test converting ANSI colors to HTML spans."""
        # Red text
        input_text = "\x1b[31mError message\x1b[0m"
        result = convert_ansi_to_html(input_text)
        assert '<span class="ansi-red">Error message</span>' in result

        # Green text
        input_text = "\x1b[32mSuccess message\x1b[0m"
        result = convert_ansi_to_html(input_text)
        assert '<span class="ansi-green">Success message</span>' in result

    def test_convert_ansi_to_html_bright_colors(self):
        """Test converting bright ANSI colors to HTML spans."""
        # Bright yellow
        input_text = "\x1b[93mWarning message\x1b[0m"
        result = convert_ansi_to_html(input_text)
        assert '<span class="ansi-bright-yellow">Warning message</span>' in result

    def test_convert_ansi_to_html_xss_protection(self):
        """Test that HTML characters are escaped for XSS protection."""
        input_text = "\x1b[31m<script>alert('xss')</script>\x1b[0m"
        result = convert_ansi_to_html(input_text)
        assert "&lt;script&gt;" in result
        assert "&lt;/script&gt;" in result
        assert "<script>" not in result

    def test_convert_ansi_to_html_no_ansi(self):
        """Test that normal text is HTML-escaped but otherwise unchanged."""
        input_text = "Normal text with <tag>"
        result = convert_ansi_to_html(input_text)
        assert result == "Normal text with &lt;tag&gt;"

    def test_sanitize_log_message_strip_ansi(self):
        """Test log message sanitization with ANSI stripping."""
        input_message = "\x1b[31mError: \x1b[0mSomething went wrong"
        result = sanitize_log_message(input_message, strip_ansi=True)
        assert result == "Error: Something went wrong"

    def test_sanitize_log_message_convert_ansi(self):
        """Test log message sanitization with ANSI to HTML conversion."""
        input_message = "\x1b[31mError\x1b[0m"
        result = sanitize_log_message(input_message, strip_ansi=False)
        assert '<span class="ansi-red">Error</span>' in result

    def test_sanitize_log_message_length_limit(self):
        """Test that extremely long messages are truncated."""
        long_message = "A" * 15000  # Longer than default max_length of 10000
        result = sanitize_log_message(long_message, max_length=10000)
        assert len(result) <= 10000 + len(" [... truncated]")
        assert result.endswith(" [... truncated]")

    def test_sanitize_log_message_empty_none(self):
        """Test handling of empty or None messages."""
        assert sanitize_log_message("") == ""
        assert sanitize_log_message(None) is None

    def test_parse_log_line_with_timestamp(self):
        """Test parsing log lines with RFC3339 timestamps."""
        # Standard log line with timestamp
        log_line = "2021-09-01T12:34:56.123456789Z This is a test message"
        result = parse_log_line(log_line)
        
        assert result["timestamp"] == "2021-09-01T12:34:56.123456789Z"
        assert result["message"] == "This is a test message"

    def test_parse_log_line_with_ansi(self):
        """Test parsing log lines with ANSI codes."""
        log_line = "2021-09-01T12:34:56Z \x1b[31mError message\x1b[0m"
        result = parse_log_line(log_line, strip_ansi=True)
        
        assert result["timestamp"] == "2021-09-01T12:34:56Z"
        assert result["message"] == "Error message"

    def test_parse_log_line_no_timestamp(self):
        """Test parsing log lines without timestamps."""
        log_line = "This is just a message without timestamp"
        result = parse_log_line(log_line)
        
        assert result["timestamp"] is None
        assert result["message"] == "This is just a message without timestamp"

    def test_parse_log_line_fractional_seconds(self):
        """Test parsing timestamps with various fractional second formats."""
        # Nanoseconds
        log_line = "2021-09-01T12:34:56.123456789Z Message"
        result = parse_log_line(log_line)
        assert result["timestamp"] == "2021-09-01T12:34:56.123456789Z"

        # Milliseconds
        log_line = "2021-09-01T12:34:56.123Z Message"
        result = parse_log_line(log_line)
        assert result["timestamp"] == "2021-09-01T12:34:56.123Z"

        # No fractional seconds
        log_line = "2021-09-01T12:34:56Z Message"
        result = parse_log_line(log_line)
        assert result["timestamp"] == "2021-09-01T12:34:56Z"


class TestErrorHandling:
    """Test enhanced error handling functions."""

    def test_format_k8s_error_400_bad_request(self):
        """Test formatting of 400 Bad Request errors."""
        error = Mock()
        error.status = 400
        error.reason = "Bad Request"
        error.body = None
        
        message, status = format_k8s_error(error)
        assert status == 400
        assert "Invalid request parameters" in message

    def test_format_k8s_error_400_container_not_ready(self):
        """Test special handling for container not ready errors."""
        error = Mock()
        error.status = 400
        error.reason = "Bad Request"
        error.body = json.dumps({"message": "container not found: not ready"})
        
        message, status = format_k8s_error(error)
        assert status == 400
        assert message == "Container is not ready yet"

    def test_format_k8s_error_401_unauthorized(self):
        """Test formatting of 401 Unauthorized errors."""
        error = Mock()
        error.status = 401
        error.reason = "Unauthorized"
        error.body = None
        
        message, status = format_k8s_error(error)
        assert status == 401
        assert "Authentication required" in message

    def test_format_k8s_error_403_forbidden(self):
        """Test formatting of 403 Forbidden errors."""
        error = Mock()
        error.status = 403
        error.reason = "Forbidden"
        error.body = None
        
        message, status = format_k8s_error(error)
        assert status == 403
        assert "Access denied" in message

    def test_format_k8s_error_404_not_found(self):
        """Test formatting of 404 Not Found errors."""
        error = Mock()
        error.status = 404
        error.reason = "Not Found"
        error.body = None
        
        message, status = format_k8s_error(error)
        assert status == 404
        assert "Resource not found" in message

    def test_format_k8s_error_429_rate_limit(self):
        """Test formatting of 429 Rate Limited errors."""
        error = Mock()
        error.status = 429
        error.reason = "Too Many Requests"
        error.body = None
        
        message, status = format_k8s_error(error)
        assert status == 429
        assert "Rate limited" in message

    def test_format_k8s_error_500_server_error(self):
        """Test formatting of 500+ server errors."""
        error = Mock()
        error.status = 500
        error.reason = "Internal Server Error"
        error.body = None
        
        message, status = format_k8s_error(error)
        assert status == 503  # Mapped to 503 for user display
        assert "Kubernetes cluster error" in message

    def test_format_k8s_error_with_body_json(self):
        """Test error formatting with JSON body details."""
        error = Mock()
        error.status = 422
        error.reason = "Unprocessable Entity"
        error.body = json.dumps({"message": "Custom error message from API"})
        
        message, status = format_k8s_error(error)
        assert status == 422
        assert "Custom error message from API" in message

    def test_format_k8s_error_with_body_invalid_json(self):
        """Test error formatting with invalid JSON body."""
        error = Mock()
        error.status = 422
        error.reason = "Unprocessable Entity"
        error.body = "Not valid JSON content"
        
        message, status = format_k8s_error(error)
        assert status == 422
        assert "Not valid JSON content" in message

    def test_create_error_log_entry(self):
        """Test creation of standardized error log entries."""
        entry = create_error_log_entry(
            pod_name="test-pod",
            container_name="test-container",
            error_message="Test error message",
            error_type="test_error"
        )
        
        assert entry["pod_name"] == "test-pod"
        assert entry["container_name"] == "test-container"
        assert entry["timestamp"] is None
        assert entry["message"] == "[TEST_ERROR] Test error message"
        assert entry["error"] is True
        assert entry["error_type"] == "test_error"

    def test_create_error_log_entry_default_type(self):
        """Test error log entry creation with default error type."""
        entry = create_error_log_entry(
            pod_name="test-pod",
            container_name=None,
            error_message="Test error"
        )
        
        assert entry["error_type"] == "api_error"
        assert entry["message"] == "[API_ERROR] Test error"


class TestRetryLogic:
    """Test retry logic functionality."""

    def test_retry_k8s_operation_success_first_try(self):
        """Test that successful operations don't retry."""
        @retry_k8s_operation(max_retries=3)
        def successful_operation():
            return "success"
        
        result = successful_operation()
        assert result == "success"

    def test_retry_k8s_operation_eventual_success(self):
        """Test that operations succeed after retries."""
        call_count = 0
        
        @retry_k8s_operation(max_retries=3, initial_delay=0.01)
        def eventually_successful_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                error = ApiException(status=500, reason="Server Error")
                raise error
            return "success"
        
        result = eventually_successful_operation()
        assert result == "success"
        assert call_count == 3

    def test_retry_k8s_operation_no_retry_on_client_error(self):
        """Test that 4xx errors are not retried."""
        call_count = 0
        
        @retry_k8s_operation(max_retries=3)
        def client_error_operation():
            nonlocal call_count
            call_count += 1
            error = ApiException(status=404, reason="Not Found")
            raise error
        
        with pytest.raises(ApiException) as exc_info:
            client_error_operation()
        
        assert exc_info.value.status == 404
        assert call_count == 1  # Should not retry

    def test_retry_k8s_operation_retry_on_server_error(self):
        """Test that 5xx errors are retried."""
        call_count = 0
        
        @retry_k8s_operation(max_retries=2, initial_delay=0.01)
        def server_error_operation():
            nonlocal call_count
            call_count += 1
            error = ApiException(status=503, reason="Service Unavailable")
            raise error
        
        with pytest.raises(ApiException) as exc_info:
            server_error_operation()
        
        assert exc_info.value.status == 503
        assert call_count == 3  # Initial attempt + 2 retries

    def test_retry_k8s_operation_no_retry_on_non_api_exception(self):
        """Test that non-API exceptions are not retried."""
        call_count = 0
        
        @retry_k8s_operation(max_retries=3)
        def non_api_error_operation():
            nonlocal call_count
            call_count += 1
            raise ValueError("Not an API exception")
        
        with pytest.raises(ValueError):
            non_api_error_operation()
        
        assert call_count == 1  # Should not retry

    def test_retry_k8s_operation_exponential_backoff(self):
        """Test that retry delays follow exponential backoff."""
        call_times = []
        
        @retry_k8s_operation(max_retries=2, initial_delay=0.1, backoff_factor=2.0)
        def always_fails():
            import time
            call_times.append(time.time())
            error = ApiException(status=503, reason="Service Unavailable")
            raise error
        
        with pytest.raises(ApiException):
            always_fails()
        
        assert len(call_times) == 3  # Initial + 2 retries
        
        # Check that delays are increasing (allowing for some timing variance)
        if len(call_times) >= 3:
            delay1 = call_times[1] - call_times[0]
            delay2 = call_times[2] - call_times[1]
            # Second delay should be roughly twice the first
            assert delay2 > delay1 * 1.5  # Allow some variance


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple functions."""

    def test_log_processing_pipeline_with_ansi(self):
        """Test the complete log processing pipeline with ANSI codes."""
        # Simulate a log line with ANSI codes and timestamp
        raw_log = "2021-09-01T12:34:56Z \x1b[31m[ERROR]\x1b[0m Application failed to start"
        
        # Process through parse_log_line (strip ANSI)
        parsed = parse_log_line(raw_log, strip_ansi=True)
        
        assert parsed["timestamp"] == "2021-09-01T12:34:56Z"
        assert parsed["message"] == "[ERROR] Application failed to start"
        assert "\x1b[" not in parsed["message"]

    def test_log_processing_pipeline_with_ansi_to_html(self):
        """Test log processing pipeline converting ANSI to HTML."""
        raw_log = "2021-09-01T12:34:56Z \x1b[32m[INFO]\x1b[0m Application started"
        
        # Process through parse_log_line (convert ANSI)
        parsed = parse_log_line(raw_log, strip_ansi=False)
        
        assert parsed["timestamp"] == "2021-09-01T12:34:56Z"
        assert '<span class="ansi-green">[INFO]</span>' in parsed["message"]

    def test_error_handling_with_container_readiness(self):
        """Test error handling for container readiness scenarios."""
        # Simulate container not ready error
        error = Mock()
        error.status = 400
        error.reason = "Bad Request"
        error.body = json.dumps({
            "message": "container log-gen in pod test-pod is not ready, state: ContainerCreating"
        })
        
        message, status = format_k8s_error(error)
        assert status == 400
        assert message == "Container is not ready yet"

    def test_comprehensive_error_log_entry_creation(self):
        """Test creating error log entries for various scenarios."""
        # API error
        api_error_entry = create_error_log_entry(
            pod_name="failed-pod",
            container_name="app",
            error_message="Failed to fetch logs: pod not found",
            error_type="log_fetch_error"
        )
        
        assert api_error_entry["error"] is True
        assert api_error_entry["message"] == "[LOG_FETCH_ERROR] Failed to fetch logs: pod not found"
        
        # Internal error
        internal_error_entry = create_error_log_entry(
            pod_name="crashed-pod",
            container_name=None,
            error_message="Unexpected error occurred",
            error_type="internal_error"
        )
        
        assert internal_error_entry["container_name"] is None
        assert internal_error_entry["message"] == "[INTERNAL_ERROR] Unexpected error occurred"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])