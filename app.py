import os
import re
from flask import Flask, jsonify, request, send_from_directory, redirect
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import logging
from functools import wraps
from flask import (
    session,
    render_template_string,
)
import json
import threading  # Added for log archival watcher

# --- Log Archiver Imports ---
from log_archiver import start_log_cleanup_job, watch_pods_and_archive

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
KUBE_POD_NAME = os.environ.get("K8S_POD_NAME", "NOT-SET")
app.logger.info(f"Targeting Kubernetes namespace: {KUBE_NAMESPACE}")

# --- Log Archival Configuration ---
RETAIN_ALL_POD_LOGS = os.environ.get("RETAIN_ALL_POD_LOGS", "false").lower() == "true"
MAX_LOG_RETENTION_MINUTES = int(
    os.environ.get("MAX_LOG_RETENTION_MINUTES", "10080")
)  # Default 7 days
LOG_DIR = "/logs"

if RETAIN_ALL_POD_LOGS:
    if not os.path.exists(LOG_DIR):
        try:
            os.makedirs(LOG_DIR)
            app.logger.info(f"Created log directory: {LOG_DIR}")
        except OSError as e:
            app.logger.error(f"Failed to create log directory {LOG_DIR}: {e}")
            # Potentially exit or disable archival if directory creation fails
            RETAIN_ALL_POD_LOGS = False  # Disable if cannot create dir

app.logger.info(f"Targeting Kubernetes namespace: {KUBE_NAMESPACE}")

app.secret_key = os.urandom(24)  # Required for session

# --- Start Background Jobs (if applicable) ---
if RETAIN_ALL_POD_LOGS:
    # Start the log cleanup job
    start_log_cleanup_job(LOG_DIR, MAX_LOG_RETENTION_MINUTES, app.logger)
    # Start the pod watcher and log archiver job
    app.logger.info("Log archival enabled. Starting pod watcher...")
    watch_thread = threading.Thread(
        target=watch_pods_and_archive,
        args=(KUBE_NAMESPACE, v1, LOG_DIR, app.logger),
        daemon=True,
    )
    watch_thread.name = "PodLogArchiverThread"
    watch_thread.start()
else:
    app.logger.info("Log archival is disabled (RETAIN_ALL_POD_LOGS is false).")


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.environ.get("API_KEY")
        if not api_key or api_key == "no-key":
            return f(*args, **kwargs)

        # Check query string first
        provided_key = request.args.get("api_key")
        # Then check header
        if not provided_key:
            provided_key = request.headers.get("X-API-Key")
        # Finally check session
        if not provided_key:
            provided_key = session.get("api_key")

        if not provided_key or provided_key != api_key:
            if request.headers.get("Accept") == "application/json":
                return jsonify({"error": "API key required"}), 401
            return render_template_string(
                """
                <form method="POST" action="/login">
                    <h2>API Key Required</h2>
                    <input type="text" name="api_key" placeholder="Enter API Key">
                    <button type="submit">Submit</button>
                </form>
            """
            )
        return f(*args, **kwargs)

    return decorated


@app.route("/login", methods=["POST"])
def login():
    api_key = os.environ.get("API_KEY")
    provided_key = request.form.get("api_key")

    if not api_key or api_key == "no-key":
        session["api_key"] = "no-key"
        app.logger.info("Login successful - no API key required")
        return redirect(request.referrer or "/")

    if provided_key == api_key:
        session["api_key"] = provided_key
        app.logger.info("Login successful with valid API key")
        return redirect(request.referrer or "/")

    app.logger.warning("Login failed - invalid API key provided")
    return jsonify({"error": "Invalid API key"}), 401


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
@require_api_key
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
    Returns a JSON object with the namespace, a list of pod names, and the current pod name.
    """
    global KUBE_NAMESPACE, KUBE_POD_NAME  # Use the globally configured namespace and pod name
    app.logger.info(f"Request for /api/pods in namespace '{KUBE_NAMESPACE}'")
    try:
        pod_list_response = v1.list_namespaced_pod(namespace=KUBE_NAMESPACE)
        pod_names = [pod.metadata.name for pod in pod_list_response.items]
        app.logger.info(f"Found {len(pod_names)} pods in namespace '{KUBE_NAMESPACE}'.")
        return jsonify(
            {
                "namespace": KUBE_NAMESPACE,
                "pods": pod_names,
                "current_pod": KUBE_POD_NAME,
            }
        )
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
        - follow (optional): If true, stream logs in real-time.
    Returns a JSON object with a list of log entries, each with 'timestamp' and 'message'.
    """
    global KUBE_NAMESPACE
    pod_name = request.args.get("pod_name")
    sort_order = request.args.get("sort_order", "desc").lower()
    tail_lines_str = request.args.get("tail_lines", "100")
    search_string = request.args.get("search_string", "").strip().lower()
    follow = request.args.get("follow", "false").lower() == "true"

    app.logger.info(
        f"Request for /api/logs: pod='{pod_name}', sort='{sort_order}', lines='{tail_lines_str}', search='{search_string}', follow='{follow}'"
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
            follow=follow,  # Enable following logs if requested
            _preload_content=not follow,  # Set to False for streaming when following
        )

        if follow:

            def generate():
                try:
                    for line in log_data_stream:
                        if not line:  # Skip empty lines
                            continue

                        # Decode bytes to string if needed
                        if isinstance(line, bytes):
                            line = line.decode("utf-8")

                        log_entry = parse_log_line(line)

                        # Apply search filter (case-insensitive)
                        if (
                            search_string
                            and search_string not in log_entry["message"].lower()
                        ):
                            continue  # Skip if search string not found

                        # Send each log entry as a Server-Sent Event
                        yield f"data: {json.dumps(log_entry)}\n\n"
                except Exception as e:
                    app.logger.error(f"Error in log stream: {str(e)}")
                    yield f"data: {json.dumps({'error': str(e)})}\n\n"

            return app.response_class(
                generate(),
                mimetype="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",  # Disable nginx buffering
                },
            )
        else:
            raw_log_lines = log_data_stream.splitlines()
            app.logger.info(
                f"Fetched {len(raw_log_lines)} raw lines for pod '{pod_name}'."
            )

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


@app.route("/api/archived_pods", methods=["GET"])
@require_api_key
def get_archived_pods():
    """
    API endpoint to list archived pod log files.
    Only active if RETAIN_ALL_POD_LOGS is true.
    Returns a JSON list of pod names for which archived logs exist.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS
    if not RETAIN_ALL_POD_LOGS:
        return (
            jsonify({"archived_pods": [], "message": "Log archival is not enabled."}),
            200,
        )

    archived_pod_names = []
    if os.path.exists(LOG_DIR):
        try:
            for filename in os.listdir(LOG_DIR):
                if filename.endswith(".log"):
                    # Remove .log extension to get pod name
                    pod_name = filename[:-4]
                    archived_pod_names.append(pod_name)
            app.logger.info(
                f"Found {len(archived_pod_names)} archived pod logs in {LOG_DIR}."
            )
        except OSError as e:
            app.logger.error(f"Error listing archived logs directory {LOG_DIR}: {e}")
            return jsonify({"message": f"Error accessing log archive: {str(e)}"}), 500
    else:
        app.logger.info(f"Log archival directory {LOG_DIR} does not exist.")

    return jsonify({"archived_pods": archived_pod_names})


@app.route("/api/archived_logs", methods=["GET"])
@require_api_key
def get_archived_logs():
    """
    API endpoint to fetch logs for a specific archived pod log file.
    Query Parameters:
        - pod_name (required): The name of the pod (filename without .log).
        - sort_order (optional, default 'desc'): 'asc' or 'desc'.
        - tail_lines (optional, default '0'): Number of lines. '0' for all.
        - search_string (optional): String to filter log messages.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS
    if not RETAIN_ALL_POD_LOGS:
        return jsonify({"message": "Log archival is not enabled."}), 403  # Forbidden

    pod_name = request.args.get("pod_name")
    sort_order = request.args.get("sort_order", "desc").lower()
    tail_lines_str = request.args.get("tail_lines", "0")  # Default to all for archived
    search_string = request.args.get("search_string", "").strip().lower()

    app.logger.info(
        f"Request for /api/archived_logs: pod='{pod_name}', sort='{sort_order}', lines='{tail_lines_str}', search='{search_string}'"
    )

    if not pod_name:
        app.logger.warning("Bad request to /api/archived_logs: pod_name missing.")
        return jsonify({"message": "Pod name is required for archived logs"}), 400

    log_file_path = os.path.join(LOG_DIR, f"{pod_name}.log")

    if not os.path.exists(log_file_path):
        app.logger.warning(f"Archived log file not found: {log_file_path}")
        return jsonify({"message": f"Archived log for pod {pod_name} not found."}), 404

    try:
        tail_lines = int(tail_lines_str) if tail_lines_str != "0" else None
        if tail_lines is not None and tail_lines < 0:
            return jsonify({"message": "tail_lines must be non-negative or 0."}), 400
    except ValueError:
        return jsonify({"message": "Invalid number for tail_lines."}), 400

    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            raw_log_lines = f.readlines()

        app.logger.info(
            f"Read {len(raw_log_lines)} lines from archived file {log_file_path}."
        )

        processed_logs = []
        for line_str in raw_log_lines:
            if not line_str.strip():
                continue
            log_entry = parse_log_line(line_str)  # Re-use existing parser
            if search_string and search_string not in log_entry["message"].lower():
                continue
            processed_logs.append(log_entry)

        app.logger.info(
            f"{len(processed_logs)} lines after search filter for archived pod '{pod_name}'."
        )

        # Apply tail_lines after filtering, before sorting if necessary
        # If tail_lines is specified, we usually want the most recent N lines from the perspective of the file's end.
        # Since we read all lines, if tail_lines is used, we take the last N of the processed_logs.
        # The sorting below will then arrange these N lines.

        # Sorting: Logs in files are typically oldest first.
        # Default behavior: oldest first (asc) from file.
        if sort_order == "desc":  # Newest first
            processed_logs.reverse()

        # Apply tail_lines AFTER sorting to get the correct N lines based on sort order
        if tail_lines is not None and tail_lines > 0:
            processed_logs = processed_logs[:tail_lines]
            # If sort was asc, tail_lines would take the first N (oldest).
            # If sort was desc, tail_lines would take the first N (newest).
            # This behavior is consistent with how `tail` command works on a sorted list.

        return jsonify({"logs": processed_logs})

    except Exception as e:
        app.logger.error(
            f"Unexpected error fetching archived logs for pod '{pod_name}': {str(e)}",
            exc_info=True,
        )
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500


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
