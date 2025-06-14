import sys

import requests
from ruamel.yaml import YAML


def get_version_branches():
    # Get version branches from github api
    response = requests.get("https://api.github.com/repos/jessegoodier/logpilot/branches")
    return [branch["name"] for branch in response.json() if branch["name"].startswith("v")]


def update_workflow_file():
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    with open(".github/workflows/helm-publisher.yml", "r") as f:
        workflow = yaml.load(f)

    # Get version branches
    version_branches = get_version_branches()
    # add main to the list of version branches
    version_branches.append("main")
    # Navigate to the options and default fields
    try:
        branch_input = workflow["on"]["workflow_dispatch"]["inputs"]["branch"]
        branch_input["options"] = version_branches
        branch_input["default"] = version_branches[0] if version_branches else "main"
    except Exception as e:
        print(f"Error updating YAML: {e}")
        sys.exit(1)

    # Write the updated workflow file
    with open(".github/workflows/helm-publisher.yml", "w") as f:
        yaml.dump(workflow, f)


if __name__ == "__main__":
    update_workflow_file()
