#!/usr/bin/env python3

import json
import os
import sys
import subprocess
from pathlib import Path
from packaging import version
import requests
from typing import Tuple, Optional

def get_current_version(repo: str) -> str:
    """Get the current version from the latest GitHub release."""
    try:
        response = requests.get(f"https://api.github.com/repos/{repo}/releases/latest")
        response.raise_for_status()
        data = response.json()
        return data.get('tag_name', 'v0.0.0').lstrip('v')
    except Exception:
        return '0.0.0'

def update_bumpversion_config(current_version: str) -> None:
    """Update the pyproject.toml file with the current version."""
    config_path = Path('pyproject.toml')
    content = config_path.read_text()
    # Update the current_version line in TOML format
    import re
    new_content = re.sub(
        r'current_version = "[^"]*"',
        f'current_version = "{current_version}"',
        content
    )
    config_path.write_text(new_content)

def get_target_version(
    version_bump: str,
    custom_version: Optional[str] = None
) -> str:
    """Get the target version based on the bump type or custom version."""
    if version_bump == 'custom':
        if not custom_version:
            raise ValueError("Custom version is required when version_bump=custom")
        return custom_version

    # Use bump-my-version to get the new version
    print(f"Running bump-my-version with {version_bump}")
    # For bump-my-version, we use show-bump to get the target version
    # First, get the current version from the release step
    current_version_cmd = subprocess.run(
        ['bump-my-version', 'bump', '--allow-dirty', '--dry-run', 'release'],
        capture_output=True,
        text=True
    )
    
    if current_version_cmd.returncode != 0:
        # If release fails, try to get current version from show command
        import re
        show_result = subprocess.run(['bump-my-version', 'show'], capture_output=True, text=True)
        for line in show_result.stdout.split('\n'):
            if "'current_version':" in line:
                # Extract version from "'current_version': '0.3.5-dev'," format
                match = re.search(r"'current_version':\s*'([^']+)'", line)
                if match:
                    current_ver = match.group(1)
                    break
        else:
            raise ValueError("Could not determine current version")
    else:
        # Get current version from show command since release worked
        import re
        show_result = subprocess.run(['bump-my-version', 'show'], capture_output=True, text=True)
        for line in show_result.stdout.split('\n'):
            if "'current_version':" in line:
                # Extract version from "'current_version': '0.3.5-dev'," format
                match = re.search(r"'current_version':\s*'([^']+)'", line)
                if match:
                    current_ver = match.group(1)
                    break
        else:
            raise ValueError("Could not determine current version")
    
    # Now show what the bump would produce
    result = subprocess.run(
        ['bump-my-version', 'show-bump', current_ver],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    
    # Parse the tree output to get the target version
    import re
    for line in result.stdout.split('\n'):
        if f'├─ {version_bump} ───' in line or f'╰─ {version_bump} ─' in line:
            # Extract version from "├─ patch ─── 0.3.6-dev" format
            match = re.search(r'─ (\d+\.\d+\.\d+(?:-\w+)?)', line)
            if match:
                return match.group(1)
    
    raise ValueError(f"Failed to get target version for {version_bump} bump")

def validate_version(current: str, target: str) -> None:
    """Validate that the target version is greater than the current version."""
    if version.Version(target) <= version.Version(current):
        raise ValueError(f"Target version {target} must be greater than current version {current}")

def show_version_suggestions(current: str, target: str) -> None:
    """Show version suggestions based on the current version."""
    # Parse version, handling pre-release suffixes like -dev
    import re
    match = re.match(r'(\d+)\.(\d+)\.(\d+)', current)
    if not match:
        print(f'ℹ️  Selected version: {target}')
        return
    major, minor, patch = map(int, match.groups())

    print('\n🚀 VERSION SUGGESTIONS 🚀')
    print('==========================')
    print(f'📦 Patch: {major}.{minor}.{patch + 1}')
    print(f'✨ Minor: {major}.{minor + 1}.0')
    print(f'🔥 Major: {major + 1}.0.0')
    print('')
    print(f'ℹ️  Selected version: {target}')

def main():
    # Get inputs from environment variables
    if os.environ.get('GITHUB_REPOSITORY') is None:
        repo = 'jessegoodier/logpilot'
    else:
        repo = os.environ.get('GITHUB_REPOSITORY')
    if os.environ.get('INPUT_VERSION_BUMP') is None:
        version_bump = 'patch'
    else:
        version_bump = os.environ.get('INPUT_VERSION_BUMP')
    custom_version = os.environ.get('INPUT_CUSTOM_VERSION')

    if not repo or not version_bump:
        raise ValueError("Missing required environment variables")

    # Get current version
    current_version = get_current_version(repo)
    print(f"Current version: {current_version}")

    # Update bumpversion config
    update_bumpversion_config(current_version)

    try:
        # Get target version
        target_version = get_target_version(version_bump, custom_version)
        print(f"Target version: {target_version}")

        # Validate version
        validate_version(current_version, target_version)

        # Show version suggestions
        show_version_suggestions(current_version, target_version)

        # Output versions for GitHub Actions
        print(f"::set-output name=version::{target_version}")
        print(f"::set-output name=current-version::{current_version}")

    except Exception as e:
        print(f"❌ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()