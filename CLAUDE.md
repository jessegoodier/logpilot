# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Safe Commands for Automated Execution

The following commands are safe to run automatically without asking for permission:

### Read-only Operations
- `git status`, `git log`, `git diff`, `git show`
- `gh run list`, `gh run view`
- `gh run view <run-id>` (view specific workflow run details)
- `gh run view <run-id> --log` (view full logs including successful steps)
- `gh run view <run-id> --log-failed` (view logs from failed steps only)
- `cat`, `head`, `tail`, `ls`, file reading operations
- `kubectl get`, `kubectl describe` (read-only kubectl commands)
- `helm list`, `helm status` (read-only helm commands)

### Code Quality & Testing
- `uv pip install -e ".[dev]"` (in virtual environment)
- `isort .` (fix import ordering)
- `isort . --check-only` (check import ordering)
- `ruff check .` (linting check)
- `ruff check . --fix` (auto-fix linting issues)
- `ruff format .` (auto-format code - replaces black)  
- `ruff format . --check` (check formatting status)
- `pytest --collect-only` (test collection without running)
- `playwright install` (browser installation)

### Environment Setup
- `uv venv` (create virtual environment)
- `source .venv/bin/activate` (activate virtual environment)
- `mkdir -p temp/` (create temp directory)
- `git checkout` (checkout any branch)
- `git pull origin` (pull any branch)
- `git checkout -b fix/new-branch-name` (create new branch)
- `git cherry-pick <commit-hash>` (cherry-pick commits)
- `gh pr view --json state --jq .state` (check PR state)
- `git reset HEAD <file>` (unstage files)
- `mv <source> <destination>` (move/rename files)
- `git add <files>` (stage files for commit)
- `git push -u origin <branch-name>` (push new branch to remote)
- `gh pr create` (create pull request)

### Analysis Commands
- `find`, `grep`, `rg` (ripgrep), search operations
- `wc`, `sort`, `uniq` (text processing)
- `docker images`, `docker ps` (read-only docker commands)

## Commands That Require Permission

### Git Operations - Always Check First
Before any git commits, ALWAYS run these safety checks:
```bash
# Check if current branch is already merged
gh pr view --json state --jq .state 2>/dev/null || echo "No PR found"

# Check if working on merged branch 
git branch -r --merged main | grep $(git branch --show-current) && echo "⚠️ BRANCH ALREADY MERGED!"

# Check current branch and status
git branch --show-current
git status
```

### Modifying Operations
- `git add`, `git commit`, `git push` (always ask before committing AND check if branch is merged)
- `ruff check . --fix`, `ruff format .` (code modification) 
- `kubectl apply`, `kubectl create`, `kubectl delete` (cluster changes)
- `helm install`, `helm upgrade`, `helm uninstall` (deployment changes)

### Test Execution
- `pytest` (actual test execution - may have side effects)
- `uv run pytest` (test execution)

### System Operations
- `sudo` commands
- Package installation outside virtual environments
- Network operations that modify state

## Git Safety Rules

### Before ANY git commit, check:
1. **Branch status**: Is this branch already merged?
2. **Working directory**: Are we in the right project?
3. **Changes**: Do the changes make sense for this branch?

### Pre-Commit Code Quality Workflow:
ALWAYS run this complete workflow before ANY commit or PR:

```bash
# 1. Essential safety checks
git branch --show-current                          # What branch am I on?
gh pr view --json state --jq .state 2>/dev/null  # Is PR already merged?
git log --oneline main..HEAD                      # What commits are ahead of main?
git status                                         # What am I about to commit?

# 2. If branch is merged, create new branch instead
if [ "$(gh pr view --json state --jq .state 2>/dev/null)" = "MERGED" ]; then
    echo "⚠️ Current branch PR is merged! Create new branch."
    echo "Run: git checkout main && git pull && git checkout -b fix/new-branch-name"
    exit 1
fi

# 3. MANDATORY: Fix all code quality issues
source .venv/bin/activate  # Ensure virtual environment is active

# Fix import ordering
isort .

# Run ruff linter and fix issues
ruff check . --fix

# Run ruff formatter (replaces black - faster and consistent)
ruff format .

# Verify everything is clean
ruff check .              # Should show "All checks passed!"
ruff format . --check     # Should show "X files already formatted"
isort . --check-only      # Should show no changes needed

echo "✅ Code quality checks completed - ready to commit!"
```

### Never commit without running code quality fixes first!

### Recovery from Merged Branch Commits:
If commits were made to a merged branch:
```bash
# 1. Check out main and pull latest
git checkout main
git pull origin main

# 2. Create new branch from main
git checkout -b fix/new-branch-name

# 3. Cherry-pick the commits you want to keep
git cherry-pick <commit-hash>

# 4. Push new branch and create fresh PR
git push -u origin fix/new-branch-name
gh pr create --title "Title" --body "Description"
```

## Development Commands

### Python envionment

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Code Quality
```bash
# Fix import ordering
uvx isort .

# Run ruff linter and fix issues
uvx ruff check --fix .

# Format code with ruff (replaces black for consistency)
uvx ruff format .
```

### Testing
```bash
# Install development dependencies
uv pip install -e ".[dev]"

# Run end-to-end tests with Playwright
uv run pytest

# Run a single test
uv run pytest tests/test_app_playwright.py::test_specific_function

# Install Playwright browsers for local testing
playwright install chromium

# Test collection only (validate tests without running)
pytest --collect-only tests/test_app_playwright.py
```

### Helm Testing
```bash
# Install helm-unittest plugin (one-time setup)
helm plugin install https://github.com/helm-unittest/helm-unittest

# Run Helm unit tests
helm unittest charts/logpilot

# Lint Helm chart
helm lint charts/logpilot

# Test template generation
helm template test-release charts/logpilot
```

### Local Development
```bash
# Create Kubernetes test resources
kubectl apply -f tests/log-gen-deployment.yaml -n log-viewer

# Port forward to test the application locally
kubectl port-forward -n log-viewer svc/logpilot-service 5001:5001

# Run the application locally (requires kubeconfig)
python src/main.py
```

### Version Management
```bash
# Check all version references across the project
./scripts/check-versions.sh

# Update all version references (for releases)
./scripts/update-versions.sh <new-version>

# Example: Update to version 0.3.0
./scripts/update-versions.sh 0.3.0
```

Note: The main branch uses placeholder version `0.0.0-dev`. The release workflow automatically updates all version references during the release process.

## GitHub Actions Debugging

### Checking Workflow Failures
```bash
# List recent workflow runs
gh run list --limit 10

# View specific workflow run details
gh run view <run-id>

# View logs from a failed run
gh run view <run-id> --log-failed

# View full logs including successful steps
gh run view <run-id> --log
```

### Local Testing Before CI
Before pushing changes that might affect GitHub Actions, test the key workflow components locally:

```bash
# 1. Test Python environment setup
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# 2. Test code quality checks (exact commands from workflow)
source .venv/bin/activate
ruff check . --output-format=json > ruff-issues.json || true
ruff format . --check --diff > ruff-format.txt 2>&1 || echo "formatting needed" > ruff-format.txt

# 3. Check for issues
cat ruff-issues.json  # Should be [] if no issues
cat ruff-format.txt   # Should show "X files already formatted" if clean

# 4. Fix any issues found
ruff check . --fix
ruff format .

# 5. Test Playwright setup
playwright install chromium
pytest --collect-only tests/test_app_playwright.py

# 6. Clean up test files
rm ruff-*.json ruff-*.txt
```

### Common GitHub Actions Issues

#### Ruff Command Issues
- **Problem**: `ruff format` doesn't support `--output-format=json` 
- **Solution**: Use `ruff format . --check --diff` for checking formatting status
- **Test locally**: Run the exact commands from the workflow to verify syntax

#### Playwright Issues
- **Problem**: Browser installation or missing dependencies
- **Solution**: Use `microsoft/playwright-github-action@v1` with explicit browser specification
- **Test locally**: `playwright install chromium` and verify test collection

#### Kubernetes Testing Issues  
- **Problem**: Timing issues with pod readiness or port forwarding
- **Solution**: Add proper wait conditions and readiness checks
- **Test locally**: Verify kubectl commands work with your cluster

#### Python Version Compatibility
- **Problem**: Different Python versions between local and CI
- **Solution**: Match CI Python version (currently 3.12) for local testing
- **Test locally**: Use same Python version as workflow matrix

### Deployment

#### Option 1: Helm Chart (Recommended)
```bash
# Install with default settings
helm install logpilot ./helm/logpilot -n log-viewer --create-namespace

# Install with custom values
helm install logpilot ./helm/logpilot -n log-viewer --create-namespace \
  --set logArchival.enabled=true \
  --set logArchival.allowPurge=false \
  --set auth.apiKey="your-secret-key"

# Install with persistent storage
helm install logpilot ./helm/logpilot -n log-viewer --create-namespace \
  --set storage.type=persistentVolume \
  --set storage.persistentVolume.size=10Gi

# Upgrade existing installation
helm upgrade logpilot ./helm/logpilot -n log-viewer

# Uninstall
helm uninstall logpilot -n log-viewer
```

#### Option 2: Raw Kubernetes Manifests
```bash
# Create ConfigMap with application code
kubectl create configmap logpilot \
  --from-file=src/main.py \
  --from-file=src/log_archiver.py \
  --from-file=src/index.html \
  --from-file=pyproject.toml \
  -n log-viewer

# Deploy the application
kubectl apply -f k8s/ -n log-viewer
```

## Architecture Overview

This is a Flask-based Kubernetes log viewer that provides a web UI for viewing pod logs with log archival capabilities.

### Core Components

- **`src/main.py`** - Main Flask application with REST API endpoints for pod listing, log fetching, and archived log management
- **`src/log_archiver.py`** - Background log archival system that watches pods and retains logs after pod termination
- **`src/index.html`** - Single-page frontend application with real-time log viewing, search, and filtering capabilities

### Key Features

- **Namespace isolation** - Only accesses pods in the configured namespace
- **Multi-container support** - Handles pods with multiple containers via pod/container notation
- **Log archival** - Configurable retention of logs from terminated pods (controlled by `RETAIN_ALL_POD_LOGS` and `MAX_LOG_RETENTION_MINUTES`)
- **API key authentication** - Optional authentication via query parameter, header, or form
- **Search and filtering** - Real-time log search with syntax highlighting
- **Theme support** - Light/dark mode toggle

### Configuration

#### Helm Values
When using the Helm chart, configuration is managed through `values.yaml`. Key settings include:

- `logArchival.enabled` - Enable/disable log archival (default: true)
- `logArchival.retentionMinutes` - Log retention period (default: 10080 = 7 days)
- `logArchival.allowPurge` - Enable/disable log purge functionality (default: true)
- `auth.apiKey` - API authentication key (default: "no-key" = disabled)
- `storage.type` - Storage type: "emptyDir" or "persistentVolume" (default: emptyDir)
- `storage.persistentVolume.size` - PVC size when using persistent storage (default: 5Gi)

#### Environment Variables
The application is configured via environment variables:
- `K8S_NAMESPACE` - Target Kubernetes namespace (default: "default")
- `K8S_POD_NAME` - Current pod name for self-exclusion
- `API_KEY` - Optional authentication key
- `RETAIN_ALL_POD_LOGS` - Enable/disable log archival (default: "false")
- `MAX_LOG_RETENTION_MINUTES` - Log retention period (default: 10080 = 7 days)
- `ALLOW_PREVIOUS_LOG_PURGE` - Enable/disable log purge functionality (default: "true")

### API Endpoints

- `GET /api/pods` - List pods and containers in namespace
- `GET /api/logs` - Fetch logs from active pods with search/filter options
- `GET /api/archived_pods` - List pods with archived logs
- `GET /api/archived_logs` - Fetch logs from archived pods
- `GET /api/logDirStats` - Get log directory statistics
- `GET /api/purgeCapability` - Check if log purge functionality is enabled
- `POST /api/purgePreviousLogs` - Clean up archived logs (requires ALLOW_PREVIOUS_LOG_PURGE=true)

### Testing Setup

The test suite uses Playwright for end-to-end testing and requires:
- A test pod (`log-gen`) running in the target namespace that generates sample logs
- The application deployed and accessible via port-forward or service
- Tests validate core functionality including log viewing, search, and filtering

### Deployment Architecture

- **RBAC** - Minimal permissions for pod listing and log reading in target namespace
- **ConfigMap** - Application code mounted as files
- **Deployment** - Single replica with resource limits and health checks
- **Service** - ClusterIP service for internal access
- **Log persistence** - EmptyDir volume for archived logs (not persistent across pod restarts)