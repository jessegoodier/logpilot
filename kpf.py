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
    all_ready = True
    for pod in pods.items:
        container_statuses = pod.status.container_statuses
        for container in container_statuses:
            print(f"{container.name} is: {container.ready}")

            if not container.ready:
                print(f"this should make the loop continue. Setting all_ready to False")
                all_ready = False
    if all_ready:
        return "G2G"
    else:
        return "Not all pods are ready"

def wait_for_pods():
    """Wait for all pods to be ready."""
    print("Waiting for all pods to be ready...")
    while True:
        result = are_all_pods_ready()
        if result == "G2G":
            print("G2G!!!")
            return
        print(result)
        time.sleep(2)

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
