#!/usr/bin/env python3

import time
from kubernetes import client, config
import subprocess
import sys

def get_current_namespace():
    """Get the current namespace from kubeconfig."""
    try:
        contexts, active_context = config.list_kube_config_contexts()
        return active_context['context']['namespace']
    except Exception:
        exit(1)

def are_all_pods_ready():
    """Check if all pods in the current namespace are ready."""
    v1 = client.CoreV1Api()
    namespace = get_current_namespace()
    pods = v1.list_namespaced_pod(namespace=namespace)

    if not pods.items:
        return "No pods found"

    for pod in pods.items:
        print(f"Pod {pod.metadata.name} is {pod.status.phase}")
        if pod.status.phase != "Running":
            for container in pod.status.container_statuses:
                if container.state.waiting:
                    print(f"Container {container.name} is not running")
            return f"{len(pod.status.container_statuses)} containers are not running"
        for container in pod.status.container_statuses:
            if not container.ready:
                return f"{len(pod.status.container_statuses)} containers are not ready"
    return "G2G"

def wait_for_pods():
    """Wait for all pods to be ready."""
    print("Waiting for all pods to be ready...")
    while True:
        result = are_all_pods_ready()
        if result == "G2G":
            break
        print(result)
        time.sleep(2)
    print("All pods are ready!")

def start_port_forward():
    """Start port forwarding to the kube-log-viewer-service."""
    print("Starting port forwarding...")
    cmd = ["kubectl", "port-forward", "svc/kube-log-viewer-service", "5001:5001", "--address", "0.0.0.0"]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error starting port forward: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nPort forwarding stopped.")

def main():
    # Load kubernetes configuration
    try:
        config.load_kube_config()
    except Exception as e:
        print(f"Error loading kubernetes config: {e}")
        sys.exit(1)
    print("Waiting for 4 seconds...")
    time.sleep(4)
    # Wait for pods to be ready
    wait_for_pods()

    # Start port forwarding
    start_port_forward()

if __name__ == "__main__":
    main()
