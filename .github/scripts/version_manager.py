#!/usr/bin/env python3

import json
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
    """Update the bumpversion.cfg file with the current version."""
    config_path = Path('.github/bumpversion.cfg')
    content = config_path.read_text()
    new_content = content.replace(
        f'current_version = {content.split("current_version = ")[1].split("\n")[0]}',
        f'current_version = {current_version}'
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
    
    # Use bump2version to get the new version
    result = subprocess.run(
        ['bump2version', '--config-file=.github/bumpversion.cfg', '--allow-dirty', '--dry-run', '--list', version_bump],
        capture_output=True,
        text=True
    )
    
    # Parse the output to get the new version
    for line in result.stdout.split('\n'):
        if line.startswith('new_version='):
            return line.split('=')[1]
    
    raise ValueError(f"Failed to get target version for {version_bump} bump")

def validate_version(current: str, target: str) -> None:
    """Validate that the target version is greater than the current version."""
    if version.Version(target) <= version.Version(current):
        raise ValueError(f"Target version {target} must be greater than current version {current}")

def show_version_suggestions(current: str, target: str) -> None:
    """Show version suggestions based on the current version."""
    major, minor, patch = map(int, current.split('.'))
    
    print('\n🚀 VERSION SUGGESTIONS 🚀')
    print('==========================')
    print(f'📦 Patch: {major}.{minor}.{patch + 1}')
    print(f'✨ Minor: {major}.{minor + 1}.0')
    print(f'🔥 Major: {major + 1}.0.0')
    print('')
    print(f'ℹ️  Selected version: {target}')

def main():
    # Get inputs from environment variables
    repo = os.environ.get('GITHUB_REPOSITORY')
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