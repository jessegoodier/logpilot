#!/bin/bash

# Script to check all version references in the project
# This helps verify that all versions are consistent

echo "=== Current Version References ==="
echo ""

echo "📦 Python Package Versions:"
echo "Root pyproject.toml:"
grep "^version = " pyproject.toml 2>/dev/null || echo "  Not found"
echo ""

echo "🐍 Python Module Versions:"
echo "Root src/__init__.py:"
grep "^__version__" src/__init__.py 2>/dev/null || echo "  Not found"
echo ""

echo "⎈ Helm Chart Versions:"
echo "Chart.yaml:"
grep -E "^(version|appVersion):" charts/logpilot/Chart.yaml 2>/dev/null || echo "  Not found"
echo ""

echo "🔍 All Version References Found:"
find . -type f \( -name "*.py" -o -name "*.toml" -o -name "*.yaml" -o -name "*.yml" \) \
  ! -path "./.git/*" ! -path "./.venv/*" ! -path "./temp/*" ! -path "./test-results/*" \
  -exec grep -l -E "(version|__version__|appVersion)" {} \; | \
  while read file; do
    echo "  $file:"
    grep -E "(^version|^__version__|^appVersion)" "$file" 2>/dev/null | sed 's/^/    /'
  done

echo ""
echo "✅ Version check completed!"