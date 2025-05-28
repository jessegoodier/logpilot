import os
import re
from flask import Flask, jsonify, request, send_from_directory
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from datetime import datetime, timezone
import logging

# --- Flask App Setup ---
app = Flask(
    __name__, static_folder=".", static_url_path=""
)  # Serve static files from current dir

# --- Logging Configuration ---
# Basic logging to see Flask and K8s client interactions
logging.basicConfig(level=logging.INFO)
# Quieter Kubernetes client library logging for routine calls, unless debugging.
logging.getLogger("kubernetes").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


# --- Kubernetes Configuration ---
# This section attempts to configure the Kubernetes client.
# It first tries in-cluster configuration (if running inside a K8s pod).
# If that fails, it tries to load the local kubeconfig file (for development).
try:
    config.load_incluster_config()
    app.logger.info("Loaded in-cluster Kubernetes configuration.")
except config.ConfigException:
    try:
        config.load_kube_config()
        app.logger.info("Loaded local Kubernetes configuration (kubeconfig).")
    except config.ConfigException as e:
        app.logger.error(
            f"Could not configure Kubernetes client: {e}. Ensure KUBECONFIG is set or app is in-cluster."
        )
        # For a real app, you might want to prevent startup or have a clear error state.
        # Here, we'll let it proceed, and API calls will fail if K8s client isn't configured.

v1 = client.CoreV1Api()  # Kubernetes CoreV1API client

# Determine Kubernetes Namespace
# Reads from 'K8S_NAMESPACE' environment variable, defaults to 'default'.
KUBE_NAMESPACE = os.environ.get("K8S_NAMESPACE", "default")
app.logger.info(f"Targeting Kubernetes namespace: {KUBE_NAMESPACE}")


# --- Helper Functions ---
def parse_log_line(line_str):
    """
    Parses a log line that typically starts with an RFC3339Nano timestamp.
    Example: "2021-09-01T12:34:56.123456789Z This is the log message."
    Returns a dictionary {'timestamp': str, 'message': str} or
    {'timestamp': None, 'message': original_line} if no timestamp is parsed.
    """
    # Regex to capture RFC3339Nano timestamp (YYYY-MM-DDTHH:MM:SS.sssssssssZ)
    # and the rest of the line as the message.
    # The (\.\d+)? part handles optional fractional seconds.
    match = re.match(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z)\s(.*)", line_str
    )
    if match:
        timestamp_str = match.group(1)
        message_str = match.group(
            3
        ).strip()  # Get the message part and strip any trailing whitespace
        return {"timestamp": timestamp_str, "message": message_str}
    else:
        # If no timestamp is found at the beginning, return the whole line as the message.
        return {"timestamp": None, "message": line_str.strip()}


# --- Routes ---
@app.route("/")
def serve_index():
    """
    Serves the main HTML page for the log viewer.
    Assumes 'index.html' (the frontend code) is in the same directory as this script.
    """
    app.logger.info(f"Serving index.html for request from {request.remote_addr}")
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/pods", methods=["GET"])
def get_pods():
    """
    API endpoint to list pods in the configured Kubernetes namespace.
    Returns a JSON object with the namespace and a list of pod names.
    """
    global KUBE_NAMESPACE  # Use the globally configured namespace
    app.logger.info(f"Request for /api/pods in namespace '{KUBE_NAMESPACE}'")
    try:
        pod_list_response = v1.list_namespaced_pod(namespace=KUBE_NAMESPACE)
        pod_names = [pod.metadata.name for pod in pod_list_response.items]
        app.logger.info(f"Found {len(pod_names)} pods in namespace '{KUBE_NAMESPACE}'.")
        return jsonify({"namespace": KUBE_NAMESPACE, "pods": pod_names})
    except ApiException as e:
        app.logger.error(
            f"Kubernetes API error fetching pods: {e.status} - {e.reason} - {e.body}"
        )
        return jsonify({"message": f"Error fetching pods: {e.reason}"}), e.status
    except Exception as e:
        app.logger.error(f"Unexpected error fetching pods: {str(e)}")
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    API endpoint to fetch logs for a specific pod.
    Query Parameters:
        - pod_name (required): The name of the pod.
        - sort_order (optional, default 'desc'): 'asc' (oldest first) or 'desc' (newest first).
        - tail_lines (optional, default '100'): Number of lines to fetch. '0' means all lines.
        - search_string (optional): String to filter log messages by (case-insensitive).
    Returns a JSON object with a list of log entries, each with 'timestamp' and 'message'.
    """
    global KUBE_NAMESPACE
    pod_name = request.args.get("pod_name")
    sort_order = request.args.get("sort_order", "desc").lower()
    tail_lines_str = request.args.get("tail_lines", "100")
    search_string = request.args.get("search_string", "").strip().lower()

    app.logger.info(
        f"Request for /api/logs: pod='{pod_name}', sort='{sort_order}', lines='{tail_lines_str}', search='{search_string}'"
    )

    if not pod_name:
        app.logger.warning("Bad request to /api/logs: pod_name missing.")
        return jsonify({"message": "Pod name is required"}), 400

    try:
        # tail_lines = None means all lines. Otherwise, convert to int.
        tail_lines = int(tail_lines_str) if tail_lines_str != "0" else None
        if tail_lines is not None and tail_lines < 0:
            app.logger.warning(
                f"Bad request to /api/logs: invalid tail_lines value {tail_lines_str}."
            )
            return (
                jsonify(
                    {
                        "message": "tail_lines must be a non-negative integer or 0 for all."
                    }
                ),
                400,
            )
    except ValueError:
        app.logger.warning(
            f"Bad request to /api/logs: invalid tail_lines value {tail_lines_str}."
        )
        return (
            jsonify({"message": "Invalid number for tail_lines. Must be an integer."}),
            400,
        )

    try:
        # Fetch logs from Kubernetes API.
        # `timestamps=True` adds timestamps to each log line.
        # `_preload_content=False` allows streaming, but here we'll read all then process.
        # If `tail_lines` is set, K8s API typically returns newest lines first.
        # If `tail_lines` is None (all logs), K8s API typically returns oldest lines first.
        log_data_stream = v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=KUBE_NAMESPACE,
            timestamps=True,
            tail_lines=tail_lines,  # Pass None to get all lines
            _preload_content=True,  # Set to True to get all content at once as string
            # If logs are huge, streaming (_preload_content=False) and line-by-line processing is better
            # For simplicity with search and sort, True is easier here.
        )

        raw_log_lines = log_data_stream.splitlines()

        app.logger.info(f"Fetched {len(raw_log_lines)} raw lines for pod '{pod_name}'.")

        processed_logs = []
        for line_str in raw_log_lines:
            if not line_str:  # Skip empty lines
                continue

            log_entry = parse_log_line(line_str)

            # Apply search filter (case-insensitive)
            if search_string and search_string not in log_entry["message"].lower():
                continue  # Skip if search string not found

            processed_logs.append(log_entry)

        app.logger.info(
            f"{len(processed_logs)} lines after search filter for pod '{pod_name}'."
        )

        # Sorting logic:
        # Kubernetes API behavior:
        # - If `tail_lines` is specified, it returns the last N lines (newest first).
        # - If `tail_lines` is None (all logs), it returns logs oldest first.

        # Default order from K8s if tail_lines is used: newest first (desc)
        # Default order from K8s if tail_lines is NOT used (all): oldest first (asc)

        if (
            tail_lines is not None
        ):  # Last N lines were requested (K8s returned newest first)
            if sort_order == "asc":
                processed_logs.reverse()  # Reverse to get oldest of the N lines first
        else:  # All logs were requested (K8s returned oldest first)
            if sort_order == "desc":
                processed_logs.reverse()  # Reverse to get newest first

        return jsonify({"logs": processed_logs})

    except ApiException as e:
        app.logger.error(
            f"Kubernetes API error fetching logs for pod '{pod_name}': {e.status} - {e.reason} - {e.body}"
        )
        error_message = e.reason
        if e.body:
            try:
                import json

                error_details = json.loads(e.body)
                error_message = error_details.get("message", e.reason)
            except json.JSONDecodeError:
                error_message = f"{e.reason} (Details: {e.body[:200]})"  # Show first 200 chars if not JSON
        return (
            jsonify(
                {"message": f"Error fetching logs for pod {pod_name}: {error_message}"}
            ),
            e.status,
        )
    except Exception as e:
        app.logger.error(
            f"Unexpected error fetching logs for pod '{pod_name}': {str(e)}",
            exc_info=True,
        )
        return (
            jsonify(
                {
                    "message": f"An unexpected error occurred while fetching logs: {str(e)}"
                }
            ),
            500,
        )


# --- Main Execution ---
if __name__ == "__main__":
    # Instructions to run:
    # 1. Save the frontend HTML (from the other immersive) as 'index.html' in the same directory as this script.
    # 2. Install dependencies: pip install Flask kubernetes
    # 3. Set K8S_NAMESPACE environment variable: export K8S_NAMESPACE="your-target-namespace"
    #    (or use 'default' namespace if not set)
    # 4. Run this script: python your_script_name.py
    # 5. Access in browser: http://localhost:5001 (or your server's IP if host='0.0.0.0')

    # Use host='0.0.0.0' to make the server accessible from other devices on the network.
    # `debug=True` is useful for development as it enables auto-reloading on code changes and provides debug info.
    # Do not use `debug=True` in a production environment.
    app.run(host="0.0.0.0", port=5001, debug=True)
