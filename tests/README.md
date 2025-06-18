# Testing Guide

This directory contains tests and testing utilities for logPilot. The tests are primarily end-to-end tests using Playwright to validate the web interface functionality.

## Quick Start

```bash
# Set up environment
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Run all tests
uv run pytest

# Run specific test
uv run pytest tests/test_app_playwright.py::test_log_viewer_e2e
```

## Test Structure

### End-to-End Tests

- **`test_app_playwright.py`** - Main Playwright-based browser tests
  - `test_log_viewer_e2e` - Basic functionality test (pod selection, log viewing, search)
  - `test_sort_order_functionality` - Log sorting and archived pods test

- **`test_auth_playwright.py`** - Authentication flow tests
  - `test_access_without_api_key_shows_form` - Login form display when auth required
  - `test_access_with_valid_api_key_in_url` - Valid API key in URL parameter
  - `test_api_key_propagated_to_backend_requests` - API key forwarding to backend
  - `test_manual_login_form_submission` - Manual login form functionality
  - `test_access_without_auth_requirement` - No-auth mode behavior

### Configuration

- **`conftest.py`** - Pytest configuration and Playwright browser settings
  - Optimized for CI environments with headless browser settings
  - Configured to ignore HTTPS errors for local testing

### Test Data

- **`log-gen-deployment.yaml`** - Kubernetes deployment for test log generator
  - Creates a pod that generates sample logs for testing
  - Used by both local testing and CI/CD workflows

## Local Testing

### Prerequisites

1. **Python Environment**:
   ```bash
   uv venv
   source .venv/bin/activate
   uv pip install -e ".[dev]"
   ```

2. **Install Playwright Browsers**:
   ```bash
   playwright install chromium
   ```

3. **Kubernetes Cluster** (for full e2e tests):
   - Kind, minikube, or any Kubernetes cluster
   - kubectl configured to access the cluster

### Running Tests Locally

#### Option 1: Full E2E Testing (Requires Kubernetes)

1. **Deploy test log generator**:
   ```bash
   kubectl create ns log-viewer-testing
   kubectl apply -f tests/log-gen-deployment.yaml -n log-viewer-testing
   ```

2. **Deploy logPilot**:
   ```bash
   # Create ConfigMap
   kubectl create configmap logpilot \
     --from-file=src/main.py \
     --from-file=src/log_archiver.py \
     --from-file=src/index.html \
     --from-file=pyproject.toml \
     -n log-viewer-testing

   # Deploy application
   kubectl apply -f k8s/ -n log-viewer-testing
   ```

3. **Wait for pods to be ready**:
   ```bash
   kubectl wait -n log-viewer-testing --for=condition=ready pod --selector app.kubernetes.io/name=logpilot --timeout=120s
   ```

4. **Start port forwarding**:
   ```bash
   kubectl port-forward -n log-viewer-testing svc/logpilot-service 5001:5001 &
   ```

5. **Run tests**:
   ```bash
   TEST_BASE_URL="http://localhost:5001" uv run pytest tests/test_app_playwright.py
   ```

#### Option 2: Individual Component Testing

1. **Test Python dependencies installation**:
   ```bash
   uv pip install -e ".[dev]"
   ```

2. **Test code quality checks**:
   ```bash
   # Check for linting issues
   uvx ruff check . --output-format=json

   # Check formatting
   uvx ruff format . --check --diff

   # Fix issues automatically
   uvx ruff check . --fix
   uvx ruff format .
   ```

3. **Test Playwright setup**:
   ```bash
   # Install browsers
   playwright install chromium

   # Verify test collection
   pytest --collect-only tests/test_app_playwright.py
   ```

#### Option 3: Local Development Testing

For rapid development iteration without full Kubernetes setup:

1. **Run logPilot locally**:
   ```bash
   # Requires kubeconfig access to a cluster with test pods
   python src/main.py
   ```

2. **Test against local instance**:
   ```bash
   TEST_BASE_URL="http://localhost:5000" uv run pytest tests/test_app_playwright.py
   ```

### Authentication Testing

Authentication tests verify that API key functionality works correctly:

1. **Test with authentication required**:
   ```bash
   # Set API key and run auth tests
   export API_KEY="test-api-key-12345"
   uv run pytest tests/test_auth_playwright.py::TestAuthenticationFlow
   ```

2. **Test with authentication disabled**:
   ```bash
   # Disable auth and test no-auth mode
   export API_KEY="no-key"
   uv run pytest tests/test_auth_playwright.py::TestNoAuthenticationFlow
   ```

3. **Run all authentication tests**:
   ```bash
   # Test both auth and no-auth scenarios
   export API_KEY="test-api-key-12345"
   uv run pytest tests/test_auth_playwright.py
   ```

## Test Configuration

### Environment Variables

- `TEST_BASE_URL` - Base URL for the application (default: `http://localhost:5001`)
- `PYTHONPATH` - Set to `.` to ensure proper imports
- `API_KEY` - Required for authentication tests (set to `test-api-key-12345` for auth tests, or `no-key` for no-auth tests)

### Browser Configuration

Tests are configured in `conftest.py` with CI-optimized settings:

- **Headless mode**: Enabled for CI environments
- **Security flags**: Disabled sandbox and GPU for containerized environments
- **HTTPS handling**: Ignores certificate errors for local testing

### Timeouts

- **Playwright operations**: 300 seconds timeout for test execution
- **Kubernetes waits**: 120 seconds for pod readiness
- **Port forwarding**: 30 seconds for service availability

## Troubleshooting

### Common Issues

1. **Port forwarding fails**:
   ```bash
   # Check if port is already in use
   lsof -i :5001
   
   # Kill existing port forwards
   pkill -f "kubectl port-forward"
   ```

2. **Tests timeout waiting for elements**:
   - Ensure logPilot is fully running and accessible
   - Check that test log generator pod is running and generating logs
   - Verify network connectivity between test runner and application

3. **Playwright browser issues**:
   ```bash
   # Reinstall browsers
   playwright install --with-deps chromium
   ```

4. **Kubernetes permission errors**:
   - Ensure RBAC is properly configured
   - Check that service account has required permissions

### Debug Mode

Run tests with verbose output:
```bash
pytest -v -s tests/test_app_playwright.py
```

Enable Playwright debug mode:
```bash
PWDEBUG=1 pytest tests/test_app_playwright.py
```

## CI/CD Integration

The tests are designed to run in GitHub Actions. See `.github/workflows/e2e_test.yml` for the complete CI configuration.

### Key CI Steps

1. **Environment Setup**: Python 3.12, uv for dependency management
2. **Code Quality**: Ruff linting and formatting checks
3. **Kubernetes**: Kind cluster with specific K8s version
4. **Application Deployment**: ConfigMap + raw manifests approach
5. **Test Execution**: Playwright with Chromium browser
6. **Artifact Collection**: Screenshots on failure

### Local CI Simulation

To simulate the CI environment locally:

```bash
# Use Python 3.12 (match CI)
# Install dependencies exactly as CI does
pip install -e ".[dev]"

# Run the same commands as CI
ruff check . --output-format=json || true
ruff format . --check --diff || true
pytest tests/test_app_playwright.py --browser chromium --timeout=300
```

## Contributing to Tests

### Adding New Tests

1. **Follow existing patterns** in `test_app_playwright.py`
2. **Use descriptive test names** that explain what is being tested
3. **Add appropriate assertions** with clear error messages
4. **Handle timing issues** with proper waits for elements
5. **Clean up resources** after tests complete

### Test Best Practices

- **Isolated tests**: Each test should be independent
- **Stable selectors**: Use data attributes or stable CSS selectors
- **Explicit waits**: Wait for elements to be visible/clickable before interacting
- **Clear assertions**: Use descriptive assertion messages
- **Error handling**: Gracefully handle expected failure scenarios

### Updating Test Configuration

When modifying test configuration:

1. **Test locally** with the new configuration
2. **Update documentation** to reflect changes
3. **Consider CI impact** - ensure changes work in containerized environments
4. **Verify browser compatibility** if changing Playwright settings