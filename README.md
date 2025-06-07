# Kube Web Log Viewer<!-- omit in toc -->

A simple Kubernetes pod log viewer web app.

Give direct log access to your software engineers to see the logs without giving them access to the kubeconfig or other centralized log tools.

This application is explicitly designed to only monitor logs of pods in the namespace it is deployed to. It can be easily adapted to view all pods in the cluster, but it may not scale well in larger environments.

![screenshot](kube-web-log-viewer.png)

## Table of Contents<!-- omit in toc -->

- [Features](#features)
- [Requirements](#requirements)
- [Deploying](#deploying)
  - [Previous Pod Logs](#previous-pod-logs)
- [Contributing](#contributing)
- [Development](#development)

## Features

- List pods in a namespace
- View and search logs from selected pods
- Sort logs (newest/oldest first)
- Automatically select pod if only one is running
- Highlight log levels (error, warning, info)
- Light/dark theme toggle
- Tailwind CSS for styling
- Modern web UI
- Flask for web server

## Requirements

- Python 3.12+
- [Flask](https://flask.palletsprojects.com/)
- [kubernetes](https://github.com/kubernetes-client/python)

## Deploying

### Option 1: Helm Chart (Recommended)

Helm allows you to easily install and customize the settings.

See the [readme](charts/README.md) in the helm chart for instructions.

### Option 2: Raw Kubernetes Manifests

1. Create the configmap:
    ```sh
    kubectl create configmap kube-web-log-viewer \
      --from-file=src/main.py \
      --from-file=src/log_archiver.py \
      --from-file=src/index.html \
      --from-file=pyproject.toml \
      -n YOUR_NAMESPACE
    ```

2. Apply the main manifest:
Modify [the app config](k8s/deployment.yaml). See comments on the API key usage.

    ```sh
    kubectl apply -f k8s/ -n YOUR_NAMESPACE
    ```

3. Port-forward to the service:

    ```sh
    kubectl port-forward -n YOUR_NAMESPACE svc/kube-web-log-viewer-service 5001:5001
    ```

The API key is designed to simply protect the UI from random users. Please use a VPN or other means to protect the app in sensitive environments.

When using an API key, you embed the key in the URL: `http://localhost:5001/?api_key=your-api-key`

### Previous Pod Logs

By default, this application stores logs for all pods in the namespace it is deployed to for 7 days.

This is configurable by setting the `MAX_LOG_RETENTION_MINUTES` environment variable in the deployment configuration.

Or disable it by setting `RETAIN_ALL_POD_LOGS=false` in the deployment configuration.

When enabled:

- Logs from all pods are stored in the `/logs` directory in the container
- Logs are automatically cleaned up after the configured retention period (default: 7 days)
- Old pod logs can be accessed through the web UI in the pod selection dropdown under "Previous Pods"
- The retention period can be configured via `MAX_LOG_RETENTION_MINUTES` environment variable
- The deployment uses emptyDir for the logs directory, so logs are not persisted across pod restarts


## Contributing

We welcome contributions! Please follow these guidelines when submitting a Pull Request:

1. Fork the repository and create your feature branch (`git checkout -b feature/amazing-feature`)
2. Make your changes
3. Test your changes, consider using the [log-gen-deployment.yaml](tests/log-gen-deployment.yaml) to test the app
   1. Feel free to make better tests
4. Run code formatting and linting:
   ```sh
   # Format code with black
   uvx black .
   # Run ruff linter
   uvx ruff check --fix .
   ```
5. Commit your changes with a descriptive commit message
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

Pull Request Guidelines

- Keep PRs focused and small when possible
- Update documentation for any new features
- Follow the existing code style
- Use clear commit messages that describe the changes
- Reference any related issues in your PR description


## Development

Testing is done with [Playwright](https://playwright.dev/).

The tests assume that the test "log-gen" pod is running in the namespace where the app is deployed.

To install development dependencies:

```sh
uv pip install -e ".[dev]"
```

To run the tests:

```sh
uv run pytest
```
