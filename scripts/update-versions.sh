#!/bin/bash

# Script to update all version references in the project
# Usage: ./scripts/update-versions.sh <new-version>

set -e

NEW_VERSION="$1"

if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <new-version>"
    echo "Example: $0 0.3.0"
    exit 1
fi

echo "Updating all version references to: $NEW_VERSION"

# Function to update version in a file with a specific pattern
update_version() {
    local file="$1"
    local pattern="$2"
    local replacement="$3"
    
    if [ -f "$file" ]; then
        echo "Updating $file"
        sed -i "$pattern" "$file"
    else
        echo "Warning: File $file not found"
    fi
}

# Define all files and their update patterns
declare -A VERSION_FILES

# Root project files
VERSION_FILES["pyproject.toml"]="s/^version = .*/version = \"$NEW_VERSION\"/"
VERSION_FILES["src/__init__.py"]="s/^__version__ = .*/__version__ = \"$NEW_VERSION\"/"

# Chart files
VERSION_FILES["charts/kube-web-log-viewer/Chart.yaml"]="s/^version:.*/version: $NEW_VERSION/; s/^appVersion:.*/appVersion: \"$NEW_VERSION\"/"
VERSION_FILES["charts/kube-web-log-viewer/pyproject.toml"]="s/^version = .*/version = \"$NEW_VERSION\"/"
VERSION_FILES["charts/kube-web-log-viewer/src/__init__.py"]="s/^__version__ = .*/__version__ = \"$NEW_VERSION\"/"

# Update all files
for file in "${!VERSION_FILES[@]}"; do
    pattern="${VERSION_FILES[$file]}"
    update_version "$file" "$pattern"
done

# Verify updates
echo ""
echo "=== Version Update Summary ==="
echo "Chart version:"
grep -E "^(version|appVersion):" charts/kube-web-log-viewer/Chart.yaml || echo "Chart.yaml not found"
echo ""
echo "Python package versions:"
grep "^version = " pyproject.toml || echo "Root pyproject.toml not found"
grep "^version = " charts/kube-web-log-viewer/pyproject.toml || echo "Chart pyproject.toml not found"
echo ""
echo "Python module versions:"
grep "^__version__" src/__init__.py || echo "Root __init__.py not found"
grep "^__version__" charts/kube-web-log-viewer/src/__init__.py || echo "Chart __init__.py not found"
echo ""
echo "Version update completed successfully!"