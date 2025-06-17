"""
Integration tests for ANSI text processing and error handling.
Tests the functionality with actual Flask app and Kubernetes cluster interactions.
"""

import json
import pytest
import requests

# Test configuration
APP_BASE_URL = "http://localhost:5001"
TEST_TIMEOUT = 30  # seconds


class TestANSIIntegration:
    """Integration tests for ANSI processing with live cluster."""

    def test_ansi_css_classes_loaded(self):
        """Test that ANSI CSS classes are properly loaded in the frontend."""
        response = requests.get(APP_BASE_URL, timeout=TEST_TIMEOUT)
        assert response.status_code == 200

        # Check that ANSI CSS classes are present
        html_content = response.text
        assert ".ansi-red" in html_content
        assert ".ansi-green" in html_content
        assert ".ansi-blue" in html_content
        assert ".ansi-bright-yellow" in html_content
        assert ".log-error" in html_content
        assert ".retry-button" in html_content

    def test_error_handling_css_styles(self):
        """Test that error handling CSS styles are loaded."""
        response = requests.get(APP_BASE_URL, timeout=TEST_TIMEOUT)
        assert response.status_code == 200

        html_content = response.text
        # Check for error styling classes
        assert "log-error" in html_content
        assert "retry-button" in html_content
        # Check for dark mode ANSI styles
        assert ".dark .ansi-red" in html_content


class TestAPIErrorHandling:
    """Test API error handling with enhanced error responses."""

    def test_pods_api_success_response_format(self):
        """Test that successful /api/pods responses have correct format."""
        response = requests.get(f"{APP_BASE_URL}/api/pods", timeout=TEST_TIMEOUT)
        assert response.status_code == 200

        data = response.json()
        assert "namespace" in data
        assert "pods" in data
        assert "current_pod" in data
        assert isinstance(data["pods"], list)

        # Check that pod entries have required fields
        if data["pods"]:
            pod = data["pods"][0]
            required_fields = ["id", "pod_name", "health_status", "health_reason"]
            for field in required_fields:
                assert field in pod

    def test_logs_api_with_invalid_pod(self):
        """Test logs API error handling with invalid pod name."""
        response = requests.get(
            f"{APP_BASE_URL}/api/logs", params={"pod_name": "nonexistent-pod-12345"}, timeout=TEST_TIMEOUT
        )

        # Should return an error response but still be valid JSON
        assert response.headers.get("content-type", "").startswith("application/json")

        if response.status_code != 200:
            data = response.json()
            # Check for enhanced error response format
            assert "message" in data
            assert "error_type" in data
            # Should indicate if retry is suggested
            assert "retry_suggested" in data

    def test_logs_api_with_missing_pod_name(self):
        """Test logs API error handling when pod_name is missing."""
        response = requests.get(f"{APP_BASE_URL}/api/logs", timeout=TEST_TIMEOUT)
        assert response.status_code == 400

        data = response.json()
        assert "message" in data
        assert "Pod name is required" in data["message"]

    def test_logs_api_with_invalid_tail_lines(self):
        """Test logs API error handling with invalid tail_lines parameter."""
        response = requests.get(
            f"{APP_BASE_URL}/api/logs", params={"pod_name": "test-pod", "tail_lines": "invalid"}, timeout=TEST_TIMEOUT
        )
        assert response.status_code == 400

        data = response.json()
        assert "message" in data
        assert "Invalid number for tail_lines" in data["message"]

    def test_logs_api_with_negative_tail_lines(self):
        """Test logs API error handling with negative tail_lines."""
        response = requests.get(
            f"{APP_BASE_URL}/api/logs", params={"pod_name": "test-pod", "tail_lines": "-5"}, timeout=TEST_TIMEOUT
        )
        assert response.status_code == 400

        data = response.json()
        assert "message" in data
        assert "tail_lines must be non-negative" in data["message"]


class TestLogProcessingIntegration:
    """Test log processing functionality with actual log data."""

    def test_log_parsing_with_timestamps(self):
        """Test that logs with timestamps are properly parsed."""
        # Get logs from any available pod
        pods_response = requests.get(f"{APP_BASE_URL}/api/pods", timeout=TEST_TIMEOUT)
        assert pods_response.status_code == 200

        pods_data = pods_response.json()
        if not pods_data["pods"]:
            pytest.skip("No pods available for testing")

        # Get first available pod
        test_pod = pods_data["pods"][0]["id"]

        logs_response = requests.get(
            f"{APP_BASE_URL}/api/logs", params={"pod_name": test_pod, "tail_lines": "5"}, timeout=TEST_TIMEOUT
        )

        if logs_response.status_code == 200:
            logs_data = logs_response.json()
            assert "logs" in logs_data

            # Check that logs have expected format
            for log_entry in logs_data["logs"]:
                assert "message" in log_entry
                assert "pod_name" in log_entry
                # timestamp can be None for some log entries
                if "timestamp" in log_entry and log_entry["timestamp"]:
                    # Should be ISO format timestamp
                    assert "T" in log_entry["timestamp"]
                    assert "Z" in log_entry["timestamp"]

    def test_search_functionality_with_ansi_processing(self):
        """Test search functionality works with ANSI-processed logs."""
        # Get logs from any available pod
        pods_response = requests.get(f"{APP_BASE_URL}/api/pods", timeout=TEST_TIMEOUT)
        assert pods_response.status_code == 200

        pods_data = pods_response.json()
        if not pods_data["pods"]:
            pytest.skip("No pods available for testing")

        test_pod = pods_data["pods"][0]["id"]

        # Search for common log terms
        search_terms = ["INFO", "ERROR", "WARN", "started", "ready"]

        for search_term in search_terms:
            logs_response = requests.get(
                f"{APP_BASE_URL}/api/logs",
                params={"pod_name": test_pod, "search_string": search_term, "tail_lines": "10"},
                timeout=TEST_TIMEOUT,
            )

            if logs_response.status_code == 200:
                logs_data = logs_response.json()
                if logs_data["logs"]:
                    # All returned logs should contain the search term
                    for log_entry in logs_data["logs"]:
                        if not log_entry.get("error", False):
                            message = log_entry["message"].lower()
                            assert search_term.lower() in message
                    break  # Found logs with this search term, test passed

    def test_case_sensitive_search(self):
        """Test case-sensitive vs case-insensitive search functionality."""
        # Get logs from any available pod
        pods_response = requests.get(f"{APP_BASE_URL}/api/pods", timeout=TEST_TIMEOUT)
        assert pods_response.status_code == 200

        pods_data = pods_response.json()
        if not pods_data["pods"]:
            pytest.skip("No pods available for testing")

        test_pod = pods_data["pods"][0]["id"]

        # Test case-insensitive search
        case_insensitive_response = requests.get(
            f"{APP_BASE_URL}/api/logs",
            params={"pod_name": test_pod, "search_string": "INFO", "case_sensitive": "false", "tail_lines": "20"},
            timeout=TEST_TIMEOUT,
        )

        # Test case-sensitive search
        case_sensitive_response = requests.get(
            f"{APP_BASE_URL}/api/logs",
            params={"pod_name": test_pod, "search_string": "INFO", "case_sensitive": "true", "tail_lines": "20"},
            timeout=TEST_TIMEOUT,
        )

        if case_insensitive_response.status_code == 200 and case_sensitive_response.status_code == 200:
            insensitive_data = case_insensitive_response.json()
            sensitive_data = case_sensitive_response.json()

            # Case-insensitive should generally return more or equal results
            # (unless all instances happen to be uppercase)
            insensitive_count = len(insensitive_data.get("logs", []))
            sensitive_count = len(sensitive_data.get("logs", []))

            assert insensitive_count >= sensitive_count


class TestContainerReadinessHandling:
    """Test special handling for container readiness scenarios."""

    def test_all_pods_view_handles_mixed_states(self):
        """Test that 'all' pods view handles pods in various states."""
        response = requests.get(
            f"{APP_BASE_URL}/api/logs", params={"pod_name": "all", "tail_lines": "10"}, timeout=TEST_TIMEOUT
        )

        # Should always return a valid response
        assert response.status_code == 200
        data = response.json()
        assert "logs" in data

        # Logs can be empty or contain entries from various pods
        # Check that any error entries are properly formatted
        for log_entry in data["logs"]:
            if log_entry.get("error", False):
                assert "message" in log_entry
                assert "error_type" in log_entry
                assert "pod_name" in log_entry

    def test_sort_order_parameter_handling(self):
        """Test that sort_order parameter is properly handled."""
        pods_response = requests.get(f"{APP_BASE_URL}/api/pods", timeout=TEST_TIMEOUT)
        assert pods_response.status_code == 200

        pods_data = pods_response.json()
        if not pods_data["pods"]:
            pytest.skip("No pods available for testing")

        test_pod = pods_data["pods"][0]["id"]

        # Test ascending sort
        asc_response = requests.get(
            f"{APP_BASE_URL}/api/logs",
            params={"pod_name": test_pod, "sort_order": "asc", "tail_lines": "5"},
            timeout=TEST_TIMEOUT,
        )

        # Test descending sort
        desc_response = requests.get(
            f"{APP_BASE_URL}/api/logs",
            params={"pod_name": test_pod, "sort_order": "desc", "tail_lines": "5"},
            timeout=TEST_TIMEOUT,
        )

        # Both should be valid
        assert asc_response.status_code == 200
        assert desc_response.status_code == 200

        # Check that response format is consistent
        asc_data = asc_response.json()
        desc_data = desc_response.json()

        assert "logs" in asc_data
        assert "logs" in desc_data


class TestRetryFunctionalityIntegration:
    """Test retry functionality in real scenarios."""

    def test_concurrent_api_calls(self):
        """Test that multiple concurrent API calls work properly with retry logic."""
        import concurrent.futures

        def make_api_call(call_id):
            try:
                response = requests.get(f"{APP_BASE_URL}/api/pods", timeout=10)
                return (call_id, response.status_code, len(response.content))
            except Exception as e:
                return (call_id, "error", str(e))

        # Make multiple concurrent calls
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_api_call, i) for i in range(10)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        # All calls should eventually succeed
        success_count = sum(1 for _, status, _ in results if status == 200)
        assert success_count >= 8  # Allow for some failures due to rate limiting

    def test_version_endpoint_availability(self):
        """Test that version endpoint works and includes new functionality marker."""
        response = requests.get(f"{APP_BASE_URL}/api/version", timeout=TEST_TIMEOUT)
        assert response.status_code == 200

        data = response.json()
        assert "version" in data
        # Version should be a string
        assert isinstance(data["version"], str)


class TestErrorRecoveryScenarios:
    """Test error recovery and resilience scenarios."""

    def test_malformed_requests_handling(self):
        """Test handling of various malformed requests."""
        # Test with invalid JSON in search (though this goes in query params)
        response = requests.get(
            f"{APP_BASE_URL}/api/logs",
            params={"pod_name": "test", "search_string": "test\x00invalid"},
            timeout=TEST_TIMEOUT,
        )

        # Should handle gracefully without crashing
        assert response.status_code in [200, 400, 404, 500]

        # Response should be valid JSON
        try:
            data = response.json()
            assert isinstance(data, dict)
        except json.JSONDecodeError:
            pytest.fail("Response should be valid JSON even for malformed requests")

    def test_unicode_handling_in_search(self):
        """Test that Unicode characters in search terms are handled properly."""
        pods_response = requests.get(f"{APP_BASE_URL}/api/pods", timeout=TEST_TIMEOUT)
        assert pods_response.status_code == 200

        pods_data = pods_response.json()
        if not pods_data["pods"]:
            pytest.skip("No pods available for testing")

        test_pod = pods_data["pods"][0]["id"]

        # Test with various Unicode characters
        unicode_terms = ["café", "测试", "🚀", "привет"]

        for term in unicode_terms:
            response = requests.get(
                f"{APP_BASE_URL}/api/logs", params={"pod_name": test_pod, "search_string": term}, timeout=TEST_TIMEOUT
            )

            # Should not crash with Unicode
            assert response.status_code in [200, 404]

            if response.status_code == 200:
                data = response.json()
                assert "logs" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
