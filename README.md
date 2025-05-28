# Kube Web Log Viewer

A simple Kubernetes log viewer web app built with Flask and the Kubernetes Python client. View logs from pods in your cluster with a modern web UI.
![screenshot](kube-web-log-viewer.png)

## Table of Contents

- [Kube Log Viewer](#kube-log-viewer)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Requirements](#requirements)
  - [Docker Build \& Push](#docker-build--push)
  - [Quick Start](#quick-start)

## Features

- List pods in a namespace
- View and search logs from selected pods
- Sort logs (newest/oldest first)
- Highlight log levels (error, warning, info)
- Light/dark theme toggle

## Requirements

- Python 3.13+
- [Flask](https://flask.palletsprojects.com/)
- [kubernetes](https://github.com/kubernetes-client/python)
- [gunicorn](https://gunicorn.org/) (for production)
- Access to a Kubernetes cluster (via kubeconfig or in-cluster)

## Docker Build & Push

Edit build.sh, then build and push a multi-arch image using `build.sh`:

```sh
./build.sh
```

## Quick Start

1. Modify [the app config](log-viewer.yaml) with your image, or use mine if you trust it.
2. Create the configmap:

    ```sh
    kubectl create configmap log-viewer --from-file=app.py --from-file=index.html -n YOUR_NAMESPACE
    ```

3. Apply the main manifest:

    ```sh
    kubectl apply -f log-viewer.yaml -n YOUR_NAMESPACE
    ```

4. Port-foward to the service:

    ```sh
    kubectl port-forward -n YOUR_NAMESPACE svc/svc/kube-log-viewer-service 5001:5001
    ```
