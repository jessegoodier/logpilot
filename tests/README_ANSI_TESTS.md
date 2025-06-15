# ANSI Text Processing and Error Handling Tests

This directory contains comprehensive tests for the new ANSI text processing and enhanced error handling functionality added to logPilot.

## Test Overview

### 🎨 ANSI Text Processing Tests
- **ANSI escape sequence stripping**: Remove color codes and control sequences
- **ANSI to HTML conversion**: Convert color codes to CSS classes with XSS protection
- **Log message sanitization**: Length limits and secure processing
- **Timestamp parsing**: RFC3339 timestamp extraction with ANSI handling

### 🔄 Error Handling Tests
- **Kubernetes API error formatting**: User-friendly error messages
- **Retry logic**: Exponential backoff for transient failures
- **Error categorization**: Different handling for 4xx vs 5xx errors
- **Container readiness**: Special handling for container startup states

### 🎭 Frontend Integration Tests
- **CSS class verification**: ANSI color classes and error styling
- **Theme support**: Light/dark mode compatibility
- **Interactive elements**: Retry buttons and error display
- **Accessibility**: ARIA labels and screen reader support

## Test Files

### `test_ansi_error_handling.py`
**Unit tests for core functionality**
- `TestANSIProcessing`: ANSI escape sequence handling
- `TestErrorHandling`: Kubernetes error formatting
- `TestRetryLogic`: Retry decorator functionality
- `TestIntegrationScenarios`: End-to-end processing pipelines

### `test_integration_ansi.py`
**Integration tests with live cluster**
- `TestANSIIntegration`: CSS classes and frontend loading
- `TestAPIErrorHandling`: API error response formats
- `TestLogProcessingIntegration`: Live log processing
- `TestContainerReadinessHandling`: Container state scenarios
- `TestRetryFunctionalityIntegration`: Real-world retry scenarios
- `TestErrorRecoveryScenarios`: Resilience and recovery testing

### `test_frontend_ansi.py`
**Frontend-focused Playwright tests**
- `TestANSIRendering`: Visual color rendering
- `TestErrorDisplay`: Error message formatting and display
- `TestInteractiveFeatures`: Retry buttons and user interactions
- `TestAccessibility`: ARIA labels and screen reader compatibility

### `test_app_playwright.py` (Enhanced)
**Added new test functions to existing E2E tests**
- `test_error_handling_and_retry_functionality()`: Error simulation and retry testing
- `test_ansi_css_and_styling_loaded()`: CSS class verification

## Running Tests

### Prerequisites
```bash
# Ensure virtual environment is activated
source .venv/bin/activate

# Install test dependencies
uv pip install -e ".[dev]"

# Install Playwright browsers
playwright install chromium

# Ensure logPilot is running on localhost:5001
python src/main.py
```

### Run All ANSI Tests
```bash
# Using the test runner script
python tests/run_ansi_tests.py

# Or run individual test files
pytest tests/test_ansi_error_handling.py -v
pytest tests/test_integration_ansi.py -v
pytest tests/test_frontend_ansi.py -v
```

### Run Specific Test Categories
```bash
# Unit tests only
pytest tests/test_ansi_error_handling.py -v

# Integration tests (requires running app)
pytest tests/test_integration_ansi.py -v

# Frontend tests (requires running app + browser)
pytest tests/test_frontend_ansi.py -v

# Enhanced E2E tests
pytest tests/test_app_playwright.py::test_error_handling_and_retry_functionality -v
pytest tests/test_app_playwright.py::test_ansi_css_and_styling_loaded -v
```

### Run Tests with Coverage
```bash
# Install coverage if needed
uv pip install coverage

# Run with coverage reporting
coverage run -m pytest tests/test_ansi_error_handling.py
coverage report
coverage html  # Generate HTML coverage report
```

## Test Environment Setup

### Kubernetes Cluster Requirements
- **Running cluster**: Tests assume access to a working Kubernetes cluster
- **Pod permissions**: Service account must have permissions to list pods and read logs
- **Test pods**: Some tests benefit from having active pods generating logs
- **Namespace access**: Tests use the configured namespace (default: `default`)

### Test Data Setup
For the most comprehensive testing, ensure you have:

1. **Log-generating pods**: Deploy the test log generator:
   ```bash
   kubectl apply -f tests/log-gen-deployment.yaml -n log-viewer
   ```

2. **Multi-container pods**: For testing container selection and error scenarios

3. **Init containers**: For testing init container log handling

## Key Test Scenarios

### ANSI Processing Scenarios
- ✅ Basic color codes (red, green, blue, etc.)
- ✅ Bright/intense color variants
- ✅ Complex escape sequences with multiple codes
- ✅ Cursor movement and screen control sequences
- ✅ XSS protection through HTML escaping
- ✅ Length limiting for memory protection

### Error Handling Scenarios
- ✅ 400 Bad Request (container not ready)
- ✅ 401 Unauthorized (authentication issues)
- ✅ 403 Forbidden (permission issues)
- ✅ 404 Not Found (pod deleted)
- ✅ 429 Rate Limited (too many requests)
- ✅ 500+ Server Errors (cluster issues)
- ✅ Network timeouts and transient failures
- ✅ Malformed responses and JSON parsing errors

### Frontend Integration Scenarios  
- ✅ CSS class loading and application
- ✅ Theme switching (light/dark mode)
- ✅ Error message display with proper styling
- ✅ Retry button interaction and functionality
- ✅ Search functionality with ANSI content
- ✅ Responsive design and accessibility

## Debugging Failed Tests

### Common Issues and Solutions

**Import errors in unit tests:**
```bash
# Ensure you're in the project root and virtual environment is activated
cd /path/to/logpilot
source .venv/bin/activate
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

**Integration tests fail to connect:**
```bash
# Ensure logPilot is running
python src/main.py &
sleep 5  # Wait for startup

# Check if accessible
curl http://localhost:5001/api/pods
```

**Playwright tests fail:**
```bash
# Ensure browsers are installed
playwright install chromium

# Check if app is accessible in browser
open http://localhost:5001
```

**Kubernetes permissions issues:**
```bash
# Check service account permissions
kubectl auth can-i list pods
kubectl auth can-i get pods
kubectl auth can-i get logs
```

### Test Output Analysis

**Successful test output should show:**
- ✅ All ANSI functions handle various input types correctly
- ✅ Error messages are user-friendly and actionable
- ✅ Retry logic works with exponential backoff
- ✅ CSS classes are loaded and applied correctly
- ✅ Interactive elements respond to user actions
- ✅ Accessibility attributes are present

**Common failure patterns:**
- ❌ CSS classes missing → Check if index.html was updated correctly
- ❌ Import errors → Check Python path and virtual environment
- ❌ API timeouts → Check if logPilot app is running and accessible
- ❌ Browser errors → Check if Playwright browsers are installed

## Contributing to Tests

When adding new ANSI or error handling functionality:

1. **Add unit tests** in `test_ansi_error_handling.py`
2. **Add integration tests** in `test_integration_ansi.py` 
3. **Add frontend tests** in `test_frontend_ansi.py` if UI changes
4. **Update this README** with new test scenarios
5. **Run full test suite** to ensure no regressions

### Test Writing Guidelines

- **Use descriptive test names** that explain what is being tested
- **Test both success and failure cases** for robust coverage
- **Mock external dependencies** in unit tests when appropriate
- **Use realistic test data** that matches actual log formats
- **Include edge cases** like empty strings, Unicode, and malformed input
- **Verify error messages** are user-friendly and actionable

## Performance Considerations

These tests include performance-related scenarios:

- **Message length limits**: Verify extremely long messages are handled
- **Concurrent requests**: Test retry logic under load
- **Memory usage**: Ensure ANSI processing doesn't cause memory leaks
- **Response times**: Verify error handling doesn't slow down normal operations

## Security Testing

Security-focused test scenarios:

- **XSS prevention**: HTML escaping in ANSI-to-HTML conversion
- **Input validation**: Malformed ANSI sequences and JSON
- **Error information disclosure**: Ensure errors don't leak sensitive data
- **CSRF protection**: API error responses maintain security headers