#!/usr/bin/env python3
"""
Comprehensive testing script for logPilot.
Handles dependency management, formatting, and running all tests.
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd, description, check=True, use_venv=True):
    """Run a command and handle errors."""
    print(f"\n🔄 {description}")

    if use_venv:
        # Use the virtual environment directly
        venv_python = Path(".venv/bin/python")
        if venv_python.exists():
            cmd = [str(venv_python)] + cmd[1:]  # Replace 'python' with venv python
        else:
            print("⚠️  Virtual environment not found, using system Python")

    print(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=check, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e}")
        if e.stdout:
            print(f"stdout: {e.stdout}")
        if e.stderr:
            print(f"stderr: {e.stderr}")
        return False


def check_uv_installed():
    """Check if uv is installed."""
    try:
        subprocess.run(["uv", "--version"], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ uv is not installed. Please install it first.")
        print("Visit: https://docs.astral.sh/uv/getting-started/installation/")
        return False


def setup_environment():
    """Set up the virtual environment with all dependencies."""
    print("🚀 Setting up development environment...")

    # Sync dependencies with dev extras
    if not run_command(
        ["uv", "sync", "--extra", "dev", "--frozen"], "Installing dependencies with dev extras", use_venv=False
    ):
        return False

    return True


def format_code():
    """Format code using ruff and isort."""
    print("\n🎨 Formatting code...")

    # Get all Python files
    python_files = []
    for pattern in ["*.py", "src/**/*.py", "tests/**/*.py", "scripts/**/*.py"]:
        python_files.extend(Path(".").glob(pattern))

    if not python_files:
        print("⚠️  No Python files found to format")
        return True

    # Format with ruff
    for py_file in python_files:
        if not run_command(["python", "-m", "ruff", "format", str(py_file)], f"Formatting {py_file}"):
            return False

    # Sort imports with isort
    for py_file in python_files:
        if not run_command(["python", "-m", "isort", str(py_file)], f"Sorting imports in {py_file}"):
            return False

    return True


def lint_code():
    """Lint code using ruff."""
    print("\n🔍 Linting code...")

    return run_command(["python", "-m", "ruff", "check", ".", "--fix"], "Running ruff linter")


def run_tests(test_pattern=None):
    """Run tests using pytest."""
    print("\n🧪 Running tests...")

    if test_pattern:
        cmd = ["python", "-m", "pytest", test_pattern]
        description = f"Running tests matching: {test_pattern}"
    else:
        cmd = ["python", "-m", "pytest", "tests/"]
        description = "Running all tests"

    return run_command(cmd, description, check=False)


def run_specific_test_files():
    """Run specific test files."""
    test_files = [
        "tests/test_auth_playwright.py",
        "tests/test_app_playwright.py",
        "tests/test_frontend_ansi.py",
        "tests/test_integration_ansi.py",
        "tests/test_ansi_error_handling.py",
    ]

    print("\n🎯 Running specific test files...")

    for test_file in test_files:
        if Path(test_file).exists():
            if not run_command(["python", "-m", "pytest", test_file], f"Running {test_file}", check=False):
                print(f"⚠️  Some tests in {test_file} failed")
        else:
            print(f"⚠️  Test file {test_file} not found")


def main():
    """Main function."""
    print("🧪 logPilot Testing Suite")
    print("=" * 50)

    # Check if we're in the right directory
    if not Path("pyproject.toml").exists():
        print("❌ pyproject.toml not found. Please run this script from the project root.")
        sys.exit(1)

    # Check if uv is installed
    if not check_uv_installed():
        sys.exit(1)

    # Parse command line arguments
    args = sys.argv[1:]

    # Setup environment
    if not setup_environment():
        print("❌ Failed to set up environment")
        sys.exit(1)

    # Determine what to run based on arguments
    if not args or "all" in args:
        print("\n📋 Running full test suite...")

        if not format_code():
            print("❌ Code formatting failed")
            sys.exit(1)

        if not lint_code():
            print("❌ Code linting failed")
            sys.exit(1)

        if not run_tests():
            print("❌ Tests failed")
            sys.exit(1)

    elif "format" in args:
        if not format_code():
            sys.exit(1)

    elif "lint" in args:
        if not lint_code():
            sys.exit(1)

    elif "test" in args:
        # Find test pattern in arguments
        test_pattern = None
        for arg in args:
            if arg != "test" and not arg.startswith("-"):
                test_pattern = arg
                break

        if not run_tests(test_pattern):
            sys.exit(1)

    elif "specific" in args:
        run_specific_test_files()

    else:
        print("Usage:")
        print("  python scripts/run_tests.py [all|format|lint|test|specific] [test_pattern]")
        print("")
        print("Options:")
        print("  all      - Run full test suite (format, lint, test)")
        print("  format   - Format code with ruff and isort")
        print("  lint     - Lint code with ruff")
        print("  test     - Run tests (optionally with pattern)")
        print("  specific - Run specific test files")
        print("")
        print("Examples:")
        print("  python scripts/run_tests.py all")
        print("  python scripts/run_tests.py format")
        print("  python scripts/run_tests.py test tests/test_auth_playwright.py")
        print("  python scripts/run_tests.py specific")

    print("\n✅ Testing complete!")


if __name__ == "__main__":
    main()
