#!/usr/bin/env python3
"""
Test runner for ANSI text processing and error handling tests.
Run this script to execute all the new test functionality.
"""

import subprocess
import sys
import os


def run_tests():
    """Run all ANSI and error handling tests."""

    # Change to the project root directory
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_root)

    print("🧪 Running ANSI Text Processing and Error Handling Tests")
    print("=" * 60)

    test_files = [
        "tests/test_ansi_error_handling.py",
        "tests/test_integration_ansi.py",
        "tests/test_frontend_ansi.py",
        "tests/test_app_playwright.py::test_error_handling_and_retry_functionality",
        "tests/test_app_playwright.py::test_ansi_css_and_styling_loaded",
    ]

    results = {}

    for test_file in test_files:
        print(f"\n📋 Running {test_file}...")
        print("-" * 40)

        try:
            # Run pytest with verbose output
            result = subprocess.run(
                [sys.executable, "-m", "pytest", test_file, "-v", "--tb=short", "--color=yes"],
                capture_output=False,
                text=True,
            )

            results[test_file] = "PASSED" if result.returncode == 0 else "FAILED"

        except Exception as e:
            print(f"❌ Error running {test_file}: {e}")
            results[test_file] = "ERROR"

    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)

    passed_count = 0
    failed_count = 0

    for test_file, status in results.items():
        status_icon = "✅" if status == "PASSED" else "❌"
        print(f"{status_icon} {test_file}: {status}")

        if status == "PASSED":
            passed_count += 1
        else:
            failed_count += 1

    print(f"\n📈 Results: {passed_count} passed, {failed_count} failed")

    if failed_count == 0:
        print("🎉 All ANSI and error handling tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return 1


if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)
