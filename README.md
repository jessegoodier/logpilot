# Kube Web Log Viewer<!-- omit in toc -->

A simple Kubernetes log viewer web app. View logs from pods in your cluster with a simple web UI.

![screenshot](kube-web-log-viewer.png)

## Table of Contents<!-- omit in toc -->

- [Features](#features)
- [Requirements](#requirements)
- [Deploying](#deploying)
- [Contributing](#contributing)

## Features

- List pods in a namespace
- View and search logs from selected pods
- Sort logs (newest/oldest first)
- Follow logs (auto-refresh)
- Automatically select pod if only one is running
- Highlight log levels (error, warning, info)
- Light/dark theme toggle
- Tailwind CSS for styling
- Modern web UI
- Flask for web server

## Requirements

- Python 3.13+
- [Flask](https://flask.palletsprojects.com/)
- [kubernetes](https://github.com/kubernetes-client/python)

## Deploying

1. Modify [the app config](log-viewer.yaml). See comments on the API key usage
2. Create the configmap:

    ```sh
    kubectl create configmap log-viewer --from-file=app.py --from-file=index.html --from-file=requirements.txt -n YOUR_NAMESPACE
    ```

3. Apply the main manifest:

    ```sh
    kubectl apply -f log-viewer.yaml -n YOUR_NAMESPACE
    ```

4. Port-foward to the service:

    ```sh
    kubectl port-forward -n YOUR_NAMESPACE svc/svc/kube-log-viewer-service 5001:5001
    ```

The API key is desinged to simply protect the UI from random users. Please use a VPN or other means to protect the app in sensitive environments. Happy to accept PRs to add more security.

When using an API key, you embed the key in the URL. You can access the app at `http://localhost:5001/api_key=your-api-key`

## Contributing

We welcome contributions! Please follow these guidelines when submitting a Pull Request:

1. Fork the repository and create your feature branch (`git checkout -b feature/amazing-feature`)
2. Make your changes
3. Test your changes, consider using the [test-pod.yaml](tests/test-pod.yaml) to test the app
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
