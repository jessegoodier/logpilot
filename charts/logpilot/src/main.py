import json
import logging
import os
import re
import tempfile
import time
import zipfile
from functools import wraps
from html import escape

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    send_from_directory,
    session,
)
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# --- Version Configuration ---
__version__ = "0.7.0"

# --- Log Archiver Imports ---
from log_archiver import get_log_dir_stats, start_log_cleanup_job, watch_pods_and_archive

# --- Flask App Setup ---
app = Flask(__name__, static_folder=".", static_url_path="")  # Serve static files from current dir

# --- Logging Configuration ---
# Basic logging to see Flask and K8s client interactions
logging.basicConfig(level=logging.INFO)
# Quieter Kubernetes client library logging for routine calls, unless debugging.
logging.getLogger("kubernetes").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


# Add custom filter to prevent logging of /ready endpoint
class ReadyEndpointFilter(logging.Filter):
    def filter(self, record):
        # Check both the message and the args for the /ready endpoint
        if isinstance(record.msg, str):
            if "GET /ready" in record.msg:
                return False
        if isinstance(record.args, tuple):
            for arg in record.args:
                if isinstance(arg, str) and "GET /ready" in arg:
                    return False
        return True


# Apply filter to both Werkzeug and Flask loggers
logging.getLogger("werkzeug").addFilter(ReadyEndpointFilter())
app.logger.addFilter(ReadyEndpointFilter())

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
        app.logger.error(f"Could not configure Kubernetes client: {e}. Ensure KUBECONFIG is set or app is in-cluster.")
        # For a real app, you might want to prevent startup or have a clear error state.
        # Here, we'll let it proceed, and API calls will fail if K8s client isn't configured.

v1 = client.CoreV1Api()  # Kubernetes CoreV1API client


# --- Kubernetes Events Classes ---
@dataclass
class KubernetesEvent:
    """Represents a Kubernetes event with all relevant information."""

    namespace: Optional[str]
    involved_object_name: Optional[str]
    involved_object_kind: Optional[str]
    reason: Optional[str]
    message: Optional[str]
    first_timestamp: Optional[datetime]
    last_timestamp: Optional[datetime]
    api_version: Optional[str]
    type: Optional[str]
    count: Optional[int]
    involved_object_uid: Optional[str]

    @classmethod
    def from_v1_event(cls, event: Any) -> "KubernetesEvent":
        """Create a KubernetesEvent from a V1Event object."""
        return cls(
            namespace=event.metadata.namespace if event.metadata else None,
            involved_object_name=(event.involved_object.name if event.involved_object else None),
            involved_object_kind=(event.involved_object.kind if event.involved_object else None),
            reason=event.reason,
            message=event.message,
            first_timestamp=event.first_timestamp,
            last_timestamp=event.last_timestamp,
            api_version=(event.involved_object.api_version if event.involved_object else None),
            type=event.type,
            count=event.count,
            involved_object_uid=(
                str(event.involved_object.uid)
                if event.involved_object and hasattr(event.involved_object, "uid") and event.involved_object.uid
                else None
            ),
        )

    def to_dict(self) -> Dict:
        """Convert the event to a dictionary."""
        return {
            "namespace": self.namespace,
            "involved_object_name": self.involved_object_name,
            "involved_object_kind": self.involved_object_kind,
            "reason": self.reason,
            "message": self.message,
            "first_timestamp": (self.first_timestamp.isoformat() if self.first_timestamp else None),
            "last_timestamp": (self.last_timestamp.isoformat() if self.last_timestamp else None),
            "api_version": self.api_version,
            "type": self.type,
            "count": self.count,
            "involved_object_uid": self.involved_object_uid,
        }


# Determine Kubernetes Namespace
# Reads from 'K8S_NAMESPACE' environment variable, defaults to 'default'.
KUBE_NAMESPACE = os.environ.get("K8S_NAMESPACE", "default")
KUBE_POD_NAME = os.environ.get("K8S_POD_NAME", "NOT-SET")
app.logger.info(f"Targeting Kubernetes namespace: {KUBE_NAMESPACE}")

# --- Log Archival Configuration ---
RETAIN_ALL_POD_LOGS = os.environ.get("RETAIN_ALL_POD_LOGS", "false").lower() == "true"
MAX_LOG_RETENTION_MINUTES = int(os.environ.get("MAX_LOG_RETENTION_MINUTES", "10080"))  # Default 7 days
ALLOW_PREVIOUS_LOG_PURGE = os.environ.get("ALLOW_PREVIOUS_LOG_PURGE", "true").lower() == "true"
LOG_DIR = "/logs"

if RETAIN_ALL_POD_LOGS:
    if not os.path.exists(LOG_DIR):
        try:
            os.makedirs(LOG_DIR)
            app.logger.info(f"Created log directory: {LOG_DIR}")
        except OSError as e:
            app.logger.error(f"Failed to create log directory {LOG_DIR}: {e}")
            # Potentially exit or disable previous pod logs if directory creation fails
            RETAIN_ALL_POD_LOGS = False  # Disable if cannot create dir

app.logger.info(f"Targeting Kubernetes namespace: {KUBE_NAMESPACE}")

app.secret_key = os.urandom(24)  # Required for session

# --- Start Background Jobs (if applicable) ---
if RETAIN_ALL_POD_LOGS:
    # Start the previous pod logs cleanup job
    import threading

    start_log_cleanup_job(LOG_DIR, MAX_LOG_RETENTION_MINUTES, app.logger)
    # Start the pod watcher and previous pod logs archiver job
    app.logger.info("Previous pod logs enabled. Starting pod watcher...")
    watch_thread = threading.Thread(
        target=watch_pods_and_archive,
        args=(KUBE_NAMESPACE, v1, LOG_DIR, app.logger),
        daemon=True,
    )
    watch_thread.name = "PodLogArchiverThread"
    watch_thread.start()
else:
    app.logger.info("Previous pod logs are disabled (RETAIN_ALL_POD_LOGS is false).")


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
def get_pod_health_status(pod):
    """
    Determine the health status of a pod based on its phase and container statuses.
    Returns a dict with 'status' and 'reason' fields.
    """
    try:
        phase = pod.status.phase

        # Handle basic phases
        if phase == "Pending":
            return {"status": "pending", "reason": "Pod is pending"}
        elif phase == "Failed":
            return {"status": "failed", "reason": "Pod has failed"}
        elif phase == "Succeeded":
            return {"status": "succeeded", "reason": "Pod has succeeded"}

        # For Running phase, check container statuses
        if phase == "Running":
            if not pod.status.container_statuses:
                return {"status": "unknown", "reason": "No container status available"}

            total_containers = len(pod.status.container_statuses)
            ready_containers = sum(1 for cs in pod.status.container_statuses if cs.ready)

            if ready_containers == total_containers:
                return {"status": "healthy", "reason": f"All {total_containers} containers ready"}
            elif ready_containers > 0:
                return {"status": "partial", "reason": f"{ready_containers}/{total_containers} containers ready"}
            else:
                # Check for specific container issues
                for cs in pod.status.container_statuses:
                    if cs.state.waiting:
                        return {"status": "waiting", "reason": f"Waiting: {cs.state.waiting.reason or 'Unknown'}"}
                    elif cs.state.terminated:
                        return {
                            "status": "terminated",
                            "reason": f"Terminated: {cs.state.terminated.reason or 'Unknown'}",
                        }

                return {"status": "unhealthy", "reason": "No containers ready"}

        return {"status": "unknown", "reason": f"Unknown phase: {phase}"}

    except Exception as e:
        return {"status": "error", "reason": f"Error getting status: {str(e)}"}


def get_last_log_timestamp(pod_name, container_name=None):
    """
    Get the timestamp of the most recent log entry for a pod/container.
    Returns ISO timestamp string or None if no logs available.
    """
    try:
        # Get recent logs (last 10 lines) to find the most recent timestamp
        log_response = v1.read_namespaced_pod_log(
            name=pod_name, namespace=KUBE_NAMESPACE, container=container_name, tail_lines=10, timestamps=True
        )

        if not log_response:
            return None

        # Split into lines and find the last line with a timestamp
        lines = log_response.strip().split("\n")
        for line in reversed(lines):
            if line.strip():
                # Parse the timestamp from the log line
                parsed = parse_log_line(line)
                if parsed.get("timestamp"):
                    return parsed["timestamp"]

        return None

    except Exception:
        # If we can't get logs (permission issues, etc.), return None
        return None


def strip_ansi_codes(text):
    """
    Remove ANSI escape sequences from text.
    This includes color codes, cursor movement, and other control sequences.
    """
    # ANSI escape sequence pattern
    # Matches: ESC[ followed by parameter bytes (0x30-0x3F), then intermediate bytes (0x20-0x2F), then final byte (0x40-0x7E)
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def convert_ansi_to_html(text):
    """
    Convert basic ANSI color codes to HTML spans with CSS classes.
    Strips other ANSI codes and escapes HTML characters.
    """
    # First escape HTML characters to prevent XSS
    text = escape(text)

    # Basic ANSI color mappings to CSS classes
    color_map = {
        "30": "ansi-black",
        "90": "ansi-bright-black",
        "31": "ansi-red",
        "91": "ansi-bright-red",
        "32": "ansi-green",
        "92": "ansi-bright-green",
        "33": "ansi-yellow",
        "93": "ansi-bright-yellow",
        "34": "ansi-blue",
        "94": "ansi-bright-blue",
        "35": "ansi-magenta",
        "95": "ansi-bright-magenta",
        "36": "ansi-cyan",
        "96": "ansi-bright-cyan",
        "37": "ansi-white",
        "97": "ansi-bright-white",
    }

    # Convert basic color codes to HTML spans
    for code, css_class in color_map.items():
        text = re.sub(f"\x1b\\[{code}m", f'<span class="{css_class}">', text)

    # Handle reset codes
    text = re.sub(r"\x1B\[0m", "</span>", text)

    # Strip remaining ANSI codes
    text = strip_ansi_codes(text)

    return text


def sanitize_log_message(message, strip_ansi=True, max_length=10000):
    """
    Sanitize log message by removing/converting ANSI codes and limiting length.

    Args:
        message: Raw log message string
        strip_ansi: If True, remove ANSI codes; if False, convert to HTML
        max_length: Maximum message length (prevents memory issues)

    Returns:
        Sanitized message string
    """
    if not message:
        return message

    # Truncate extremely long messages to prevent memory issues
    if len(message) > max_length:
        message = message[:max_length] + " [... truncated]"

    # Handle ANSI codes
    if strip_ansi:
        message = strip_ansi_codes(message)
    else:
        message = convert_ansi_to_html(message)

    return message


def retry_k8s_operation(max_retries=3, initial_delay=0.5, backoff_factor=2.0):
    """
    Decorator to retry Kubernetes operations with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay between retries in seconds
        backoff_factor: Multiplier for delay between retries
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            delay = initial_delay

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except ApiException as e:
                    last_exception = e
                    # Don't retry on certain HTTP status codes
                    if e.status in [400, 401, 403, 404]:
                        break

                    if attempt < max_retries:
                        app.logger.warning(
                            f"Kubernetes API call failed (attempt {attempt + 1}/{max_retries + 1}): "
                            f"{e.status} - {e.reason}. Retrying in {delay:.1f}s..."
                        )
                        time.sleep(delay)
                        delay *= backoff_factor
                    else:
                        app.logger.error(
                            f"Kubernetes API call failed after {max_retries + 1} attempts: {e.status} - {e.reason}"
                        )
                except Exception as e:
                    last_exception = e
                    # Don't retry on non-API exceptions
                    break

            # Re-raise the last exception
            raise last_exception

        return wrapper

    return decorator


def format_k8s_error(e):
    """
    Format Kubernetes API exception into user-friendly error message.

    Args:
        e: ApiException from Kubernetes client

    Returns:
        tuple: (user_message, http_status_code)
    """
    if e.status == 400:
        # Try to extract detailed error message from response body
        error_message = e.reason
        if e.body:
            try:
                error_details = json.loads(e.body)
                message = error_details.get("message", "")
                # Check if the error is due to container not being ready
                if (
                    "not found" in message.lower()
                    or "not ready" in message.lower()
                    or "containercreating" in message.lower()
                ):
                    return "Container is not ready yet", 400
            except json.JSONDecodeError:
                pass
        return f"Invalid request parameters: {error_message}", 400
    elif e.status == 401:
        return "Authentication required - check service account permissions", 401
    elif e.status == 403:
        return "Access denied - insufficient permissions to access this resource", 403
    elif e.status == 404:
        return "Resource not found - pod may have been deleted", 404
    elif e.status == 429:
        return "Rate limited - too many requests, please try again later", 429
    elif e.status >= 500:
        return "Kubernetes cluster error - please try again later", 503
    else:
        # Try to extract detailed error message from response body
        error_message = e.reason
        if e.body:
            try:
                error_details = json.loads(e.body)
                if "message" in error_details:
                    error_message = error_details["message"]
                elif "reason" in error_details:
                    error_message = error_details["reason"]
            except json.JSONDecodeError:
                # Include truncated body if JSON parsing fails
                error_message = f"{e.reason} (Details: {e.body[:200]})"

        return f"Kubernetes API error: {error_message}", e.status


def create_error_log_entry(pod_name, container_name, error_message, error_type="api_error"):
    """
    Create a standardized error log entry for display in the log viewer.

    Args:
        pod_name: Name of the pod
        container_name: Name of the container (optional)
        error_message: Human-readable error message
        error_type: Type of error for categorization

    Returns:
        dict: Log entry with error information
    """
    return {
        "pod_name": pod_name,
        "container_name": container_name,
        "timestamp": None,
        "message": f"[{error_type.upper()}] {error_message}",
        "error": True,
        "error_type": error_type,
    }


def parse_log_line(line_str, strip_ansi=True):
    """
    Parses a log line that typically starts with an RFC3339Nano timestamp.
    Example: "2021-09-01T12:34:56.123456789Z This is the log message."
    Returns a dictionary {'timestamp': str, 'message': str} or
    {'timestamp': None, 'message': original_line} if no timestamp is parsed.

    Args:
        line_str: Raw log line string
        strip_ansi: If True, remove ANSI codes from message
    """
    # Regex to capture RFC3339Nano timestamp (YYYY-MM-DDTHH:MM:SS.sssssssssZ)
    # and the rest of the line as the message.
    # The (\.\d+)? part handles optional fractional seconds.
    match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z)\s(.*)", line_str)
    if match:
        timestamp_str = match.group(1)
        message_str = match.group(3).strip()  # Get the message part and strip any trailing whitespace
        message_str = sanitize_log_message(message_str, strip_ansi=strip_ansi)
        return {"timestamp": timestamp_str, "message": message_str}
    else:
        # If no timestamp is found at the beginning, return the whole line as the message.
        sanitized_line = sanitize_log_message(line_str.strip(), strip_ansi=strip_ansi)
        return {"timestamp": None, "message": sanitized_line}


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


@retry_k8s_operation(max_retries=2, initial_delay=0.3)
def _list_pods_with_retry():
    """Helper function to list pods with retry logic."""
    return v1.list_namespaced_pod(namespace=KUBE_NAMESPACE)


@retry_k8s_operation(max_retries=2, initial_delay=0.3)
def _fetch_pod_logs_with_retry(pod_name, container_name=None, tail_lines=None):
    """Helper function to fetch pod logs with retry logic."""
    return v1.read_namespaced_pod_log(
        name=pod_name,
        namespace=KUBE_NAMESPACE,
        container=container_name,
        timestamps=True,
        tail_lines=tail_lines,
        follow=False,
        _preload_content=True,
    )


@app.route("/api/pods", methods=["GET"])
def get_pods():
    """
    API endpoint to list pods in the configured Kubernetes namespace.
    Returns a JSON object with the namespace, detailed pod information including
    health status and last log timestamp, and the current pod name.
    """
    global KUBE_NAMESPACE, KUBE_POD_NAME
    app.logger.info(f"Request for /api/pods in namespace '{KUBE_NAMESPACE}'")

    exclude_self = request.args.get("exclude_self", "").lower() == "true"

    try:
        pod_list_response = _list_pods_with_retry()
        pod_info = []

        for pod in pod_list_response.items:
            if exclude_self and pod.metadata.name == KUBE_POD_NAME:
                continue

            pod_name = pod.metadata.name
            containers = [container.name for container in pod.spec.containers]
            init_containers = [container.name for container in (pod.spec.init_containers or [])]

            # Get pod health status
            health_info = get_pod_health_status(pod)

            # Get pod metadata
            created_time = pod.metadata.creation_timestamp.isoformat() if pod.metadata.creation_timestamp else None

            # Process init containers with "init-" prefix
            for init_container in init_containers:
                container_id = f"{pod_name}/init-{init_container}"
                last_log_time = get_last_log_timestamp(pod_name, f"init-{init_container}")

                pod_info.append(
                    {
                        "id": container_id,
                        "pod_name": pod_name,
                        "container_name": f"init-{init_container}",
                        "type": "init_container",
                        "health_status": health_info["status"],
                        "health_reason": health_info["reason"],
                        "last_log_time": last_log_time,
                        "created_time": created_time,
                    }
                )

            # Process regular containers (always use pod/container format)
            for container in containers:
                container_id = f"{pod_name}/{container}"
                last_log_time = get_last_log_timestamp(pod_name, container)

                pod_info.append(
                    {
                        "id": container_id,
                        "pod_name": pod_name,
                        "container_name": container,
                        "type": "container",
                        "health_status": health_info["status"],
                        "health_reason": health_info["reason"],
                        "last_log_time": last_log_time,
                        "created_time": created_time,
                    }
                )

        app.logger.info(f"Found {len(pod_info)} pod/container combinations in namespace '{KUBE_NAMESPACE}'")
        return jsonify(
            {
                "namespace": KUBE_NAMESPACE,
                "pods": pod_info,
                "current_pod": KUBE_POD_NAME,
            }
        )
    except ApiException as e:
        app.logger.error(f"Kubernetes API error fetching pods: {e.status} - {e.reason} - {e.body}")
        error_message, status_code = format_k8s_error(e)
        return jsonify(
            {
                "message": error_message,
                "error_type": "kubernetes_api_error",
                "retry_suggested": status_code >= 500 or status_code == 429,
            }
        ), status_code
    except Exception as e:
        app.logger.error(f"Unexpected error fetching pods: {str(e)}", exc_info=True)
        return jsonify(
            {
                "message": "An unexpected error occurred while fetching pod information",
                "error_type": "internal_error",
                "retry_suggested": False,
            }
        ), 500


@app.route("/ready", methods=["GET"])
def readiness_probe():
    """
    Readiness probe endpoint that checks if the /api/pods endpoint is working.
    Returns 200 if pods can be listed, 503 otherwise.
    Does not log requests to avoid log spam.
    """
    try:
        # Temporarily disable logging for this check
        original_level = app.logger.level
        app.logger.setLevel(logging.ERROR)

        # Try to list pods
        v1.list_namespaced_pod(namespace=KUBE_NAMESPACE)

        # Restore logging level
        app.logger.setLevel(original_level)
        return "", 200
    except Exception:
        # Restore logging level in case of error
        app.logger.setLevel(original_level)
        return "", 503


@app.route("/api/logs", methods=["GET"])
def get_logs():
    """
    API endpoint to fetch logs for a specific pod/container or all pods.
    Query Parameters:
        - pod_name (required): The name of the pod/container (format: 'pod' or 'pod/container') or 'all' for all pods.
        - sort_order (optional, default 'desc'): 'asc' (oldest first) or 'desc' (newest first).
        - tail_lines (optional, default '100'): Number of lines to fetch. '0' means all lines. When searching, all logs are fetched first, then filtered by search term, then limited by tail_lines.
        - search_string (optional): String to filter log messages by.
        - case_sensitive (optional, default 'false'): 'true' for case-sensitive search, 'false' for case-insensitive.
    Returns a JSON object with a list of log entries, each with 'timestamp', 'message', 'pod_name', and 'container_name'.
    """
    global KUBE_NAMESPACE, v1
    pod_name_req = request.args.get("pod_name")
    sort_order = request.args.get("sort_order", "desc").lower()
    tail_lines_str = request.args.get("tail_lines", "100")
    search_string = request.args.get("search_string", "").strip()
    case_sensitive = request.args.get("case_sensitive", "false").lower() == "true"

    app.logger.info(
        f"Request for /api/logs: pod='{pod_name_req}', sort='{sort_order}', lines='{tail_lines_str}', search='{search_string}'"
    )

    if not pod_name_req:
        app.logger.warning("Bad request to /api/logs: pod_name missing.")
        return jsonify({"message": "Pod name is required"}), 400

    try:
        tail_lines = int(tail_lines_str) if tail_lines_str != "0" else None
        if tail_lines is not None and tail_lines < 0:
            return jsonify({"message": "tail_lines must be non-negative or 0."}), 400
    except ValueError:
        return jsonify({"message": "Invalid number for tail_lines."}), 400

    # When searching, fetch more logs to ensure we don't miss results
    # If there's a search term, use a larger window or all logs
    k8s_tail_lines = None if search_string else tail_lines

    try:
        if pod_name_req == "all":
            pod_list_response = v1.list_namespaced_pod(namespace=KUBE_NAMESPACE)
            all_logs = []

            for pod in pod_list_response.items:
                if pod.metadata.name == KUBE_POD_NAME:
                    continue

                pod_name = pod.metadata.name

                # Process init containers first
                for init_container in pod.spec.init_containers or []:
                    container_name = f"init-{init_container.name}"
                    try:
                        log_data_stream = _fetch_pod_logs_with_retry(
                            pod_name=pod_name, container_name=init_container.name, tail_lines=k8s_tail_lines
                        )
                        raw_log_lines = log_data_stream.splitlines()
                        for line_str in raw_log_lines:
                            if not line_str:
                                continue
                            log_entry = parse_log_line(line_str)
                            if search_string:
                                search_text = log_entry["message"] if case_sensitive else log_entry["message"].lower()
                                search_term = search_string if case_sensitive else search_string.lower()
                                if search_term not in search_text:
                                    continue
                            log_entry["pod_name"] = pod_name
                            log_entry["container_name"] = container_name
                            all_logs.append(log_entry)
                    except ApiException as e:
                        app.logger.warning(
                            f"Could not fetch logs for pod {pod_name} init container {init_container.name}: {e.status} - {e.reason}"
                        )
                        error_message, _ = format_k8s_error(e)
                        error_entry = create_error_log_entry(
                            pod_name=pod_name,
                            container_name=container_name,
                            error_message=error_message,
                            error_type="log_fetch_error",
                        )
                        all_logs.append(error_entry)

                # Process regular containers
                for container in pod.spec.containers:
                    container_name = container.name
                    try:
                        log_data_stream = _fetch_pod_logs_with_retry(
                            pod_name=pod_name, container_name=container_name, tail_lines=k8s_tail_lines
                        )
                        raw_log_lines = log_data_stream.splitlines()
                        for line_str in raw_log_lines:
                            if not line_str:
                                continue
                            log_entry = parse_log_line(line_str)
                            if search_string:
                                search_text = log_entry["message"] if case_sensitive else log_entry["message"].lower()
                                search_term = search_string if case_sensitive else search_string.lower()
                                if search_term not in search_text:
                                    continue
                            log_entry["pod_name"] = pod_name
                            log_entry["container_name"] = container_name
                            all_logs.append(log_entry)
                    except ApiException as e:
                        app.logger.warning(
                            f"Could not fetch logs for pod {pod_name} container {container_name}: {e.status} - {e.reason}"
                        )
                        error_message, _ = format_k8s_error(e)
                        error_entry = create_error_log_entry(
                            pod_name=pod_name,
                            container_name=container_name,
                            error_message=error_message,
                            error_type="log_fetch_error",
                        )
                        all_logs.append(error_entry)

            all_logs.sort(
                key=lambda x: x.get("timestamp") or "0000-00-00T00:00:00Z",
                reverse=(sort_order == "desc"),
            )

            if tail_lines is not None and tail_lines > 0:
                if sort_order == "desc":
                    all_logs = all_logs[:tail_lines]
                else:
                    all_logs = all_logs[-tail_lines:]

            return jsonify({"logs": all_logs})
        else:  # Single pod/container
            # Split pod_name into pod and container if it contains a slash
            pod_name = pod_name_req
            container_name = None

            if "/" in pod_name_req:
                pod_name, container_name = pod_name_req.split("/", 1)
                # Check if this is an init container (prefixed with "init-")
                if container_name.startswith("init-"):
                    # Remove the "init-" prefix to get the actual container name
                    actual_container_name = container_name[5:]
                else:
                    actual_container_name = container_name
            else:
                actual_container_name = container_name

            log_data_stream = _fetch_pod_logs_with_retry(
                pod_name=pod_name, container_name=actual_container_name, tail_lines=k8s_tail_lines
            )

            raw_log_lines = log_data_stream.splitlines()
            processed_logs = []
            for line_str in raw_log_lines:
                if not line_str:
                    continue
                log_entry = parse_log_line(line_str)
                if search_string:
                    search_text = log_entry["message"] if case_sensitive else log_entry["message"].lower()
                    search_term = search_string if case_sensitive else search_string.lower()
                    if search_term not in search_text:
                        continue
                log_entry["pod_name"] = pod_name
                if container_name:
                    log_entry["container_name"] = container_name
                processed_logs.append(log_entry)

            processed_logs.sort(
                key=lambda x: x.get("timestamp") or "0000-00-00T00:00:00Z",
                reverse=(sort_order == "desc"),
            )

            if tail_lines is not None and tail_lines > 0:
                if sort_order == "desc":
                    processed_logs = processed_logs[:tail_lines]
                else:
                    processed_logs = processed_logs[-tail_lines:]

            return jsonify({"logs": processed_logs})

    except ApiException as e:
        app.logger.error(
            f"Kubernetes API error processing logs for '{pod_name_req}': {e.status} - {e.reason} - {e.body}"
        )
        error_message, status_code = format_k8s_error(e)

        # For container not ready, create an informational entry instead of an error
        if status_code == 400 and "not ready" in error_message.lower():
            return jsonify(
                {
                    "logs": [
                        {
                            "pod_name": pod_name_req.split("/")[0] if "/" in pod_name_req else pod_name_req,
                            "container_name": pod_name_req.split("/")[1] if "/" in pod_name_req else None,
                            "timestamp": None,
                            "message": f"[logPilot] {error_message}",
                            "error": False,
                            "error_type": "logpilot_info",
                        }
                    ]
                }
            ), 200  # Return 200 since this is an expected state

        return jsonify(
            {
                "message": error_message,
                "error_type": "kubernetes_api_error",
                "retry_suggested": status_code >= 500 or status_code == 429,
                "pod_name": pod_name_req,
            }
        ), status_code
    except Exception as e:
        app.logger.error(
            f"Unexpected error processing logs for '{pod_name_req}': {str(e)}",
            exc_info=True,
        )
        return jsonify(
            {
                "message": "An unexpected error occurred while processing log request",
                "error_type": "internal_error",
                "retry_suggested": False,
                "pod_name": pod_name_req,
            }
        ), 500


@app.route("/api/archived_pods", methods=["GET"])
@require_api_key
def get_archived_pods():
    """
    API endpoint to list previous pod log files.
    Only active if RETAIN_ALL_POD_LOGS is true.
    Returns a JSON list of pod/container names for which previous pod logs exist
    but are no longer running.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS, KUBE_NAMESPACE, v1
    if not RETAIN_ALL_POD_LOGS:
        return (
            jsonify({"archived_pods": [], "message": "Previous pod logs are not enabled."}),
            200,
        )

    archived_pod_names = []
    if os.path.exists(LOG_DIR):
        try:
            # Get list of currently running pods to exclude from archived list
            running_pod_containers = set()
            try:
                pod_list_response = v1.list_namespaced_pod(namespace=KUBE_NAMESPACE)
                for pod in pod_list_response.items:
                    pod_name = pod.metadata.name
                    containers = [container.name for container in pod.spec.containers]
                    init_containers = [container.name for container in (pod.spec.init_containers or [])]

                    # Add init containers with "init-" prefix
                    for init_container in init_containers:
                        running_pod_containers.add(f"{pod_name}/init-{init_container}")
                    for container in containers:
                        running_pod_containers.add(f"{pod_name}/{container}")
                app.logger.info(f"Found {len(running_pod_containers)} currently running pod/container combinations.")
            except ApiException as e:
                app.logger.warning(f"Could not fetch running pods for archived filter: {e.status} - {e.reason}")
                # Continue with empty set - this will show all archived pods if we can't fetch running ones
                running_pod_containers = set()

            # List archived log files and exclude currently running pods
            # Use os.walk to search subdirectories since multi-container pods create subdirectories
            for root, _, files in os.walk(LOG_DIR):
                for filename in files:
                    if filename.endswith(".log"):
                        # Get relative path from LOG_DIR to construct pod/container name
                        file_path = os.path.join(root, filename)
                        relative_path = os.path.relpath(file_path, LOG_DIR)
                        # Remove .log extension to get pod/container name
                        pod_container = relative_path[:-4]
                        # Exclude current pod and any currently running pods
                        if KUBE_POD_NAME not in pod_container and pod_container not in running_pod_containers:
                            archived_pod_names.append(pod_container)

            app.logger.info(f"Found {len(archived_pod_names)} previous (non-running) pod/container logs in {LOG_DIR}.")
        except OSError as e:
            app.logger.error(f"Error listing previous pod logs directory {LOG_DIR}: {e}")
            return jsonify({"message": f"Error accessing log archive: {str(e)}"}), 500
    else:
        app.logger.info(f"Previous pod logs directory {LOG_DIR} does not exist.")

    return jsonify({"archived_pods": archived_pod_names})


@app.route("/api/archived_logs", methods=["GET"])
@require_api_key
def get_archived_logs():
    """
    API endpoint to fetch logs for a specific previous pod/container log file.
    Query Parameters:
        - pod_name (required): The name of the pod/container (format: 'pod' or 'pod/container').
        - sort_order (optional, default 'desc'): 'asc' or 'desc'.
        - tail_lines (optional, default '0'): Number of lines. '0' for all. When searching, all logs are searched first, then filtered by search term, then limited by tail_lines.
        - search_string (optional): String to filter log messages.
        - case_sensitive (optional, default 'false'): 'true' for case-sensitive search, 'false' for case-insensitive.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS
    if not RETAIN_ALL_POD_LOGS:
        return (
            jsonify({"message": "Previous pod logs are not enabled."}),
            403,
        )  # Forbidden

    pod_name = request.args.get("pod_name")
    sort_order = request.args.get("sort_order", "desc").lower()
    tail_lines_str = request.args.get("tail_lines", "0")  # Default to all for previous
    search_string = request.args.get("search_string", "").strip()
    case_sensitive = request.args.get("case_sensitive", "false").lower() == "true"

    app.logger.info(
        f"Request for /api/archived_logs: pod='{pod_name}', sort='{sort_order}', lines='{tail_lines_str}', search='{search_string}'"
    )

    if not pod_name:
        app.logger.warning("Bad request to /api/archived_logs: pod_name missing.")
        return jsonify({"message": "Pod name is required for archived logs"}), 400

    log_file_path = os.path.join(LOG_DIR, f"{pod_name}.log")

    if not os.path.exists(log_file_path):
        app.logger.warning(f"Archived log file not found: {log_file_path}")
        return jsonify({"message": f"Previous log for pod/container {pod_name} not found."}), 404

    try:
        tail_lines = int(tail_lines_str) if tail_lines_str != "0" else None
        if tail_lines is not None and tail_lines < 0:
            return jsonify({"message": "tail_lines must be non-negative or 0."}), 400
    except ValueError:
        return jsonify({"message": "Invalid number for tail_lines."}), 400

    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            raw_log_lines = f.readlines()

        app.logger.info(f"Read {len(raw_log_lines)} lines from archived file {log_file_path}.")

        processed_logs = []
        for line_str in raw_log_lines:
            if not line_str.strip():
                continue
            log_entry = parse_log_line(line_str)
            if search_string:
                search_text = log_entry["message"] if case_sensitive else log_entry["message"].lower()
                search_term = search_string if case_sensitive else search_string.lower()
                if search_term not in search_text:
                    continue

            # Add pod and container information
            if "/" in pod_name:
                pod, container = pod_name.split("/", 1)
                log_entry["pod_name"] = pod
                log_entry["container_name"] = container
            else:
                log_entry["pod_name"] = pod_name

            processed_logs.append(log_entry)

        app.logger.info(f"{len(processed_logs)} lines after search filter for archived pod/container '{pod_name}'.")

        # Sort by timestamp
        processed_logs.sort(
            key=lambda x: x.get("timestamp") or "0000-00-00T00:00:00Z",
            reverse=(sort_order == "desc"),
        )

        if tail_lines is not None and tail_lines > 0:
            if sort_order == "desc":
                processed_logs = processed_logs[:tail_lines]
            else:
                processed_logs = processed_logs[-tail_lines:]

        return jsonify({"logs": processed_logs})

    except Exception as e:
        app.logger.error(
            f"Unexpected error fetching archived logs for pod/container '{pod_name}': {str(e)}",
            exc_info=True,
        )
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/api/logDirStats", methods=["GET"])
@require_api_key
def get_log_dir_stats_endpoint():
    """
    API endpoint to get statistics about the log directory.
    Returns:
        - total_size_miBytes: Total size of all log files in miBytes
        - file_count: Number of log files
        - oldest_file_date: Creation date of the oldest log file
        - enabled: Whether log archiving is enabled
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS

    if not RETAIN_ALL_POD_LOGS:
        return jsonify({"enabled": False, "message": "Previous pod logs are not enabled."}), 200

    if not os.path.exists(LOG_DIR):
        return (
            jsonify(
                {
                    "enabled": True,
                    "total_size_mibytes": 0,
                    "file_count": 0,
                    "oldest_file_date": None,
                    "message": "Log directory does not exist.",
                }
            ),
            200,
        )

    try:
        total_size = 0
        file_count = 0
        oldest_date = None

        # Walk through directory recursively
        for root, _, files in os.walk(LOG_DIR):
            for filename in files:
                if filename.endswith(".log"):
                    file_path = os.path.join(root, filename)
                    file_stats = os.stat(file_path)

                    # Update total size
                    total_size += file_stats.st_size
                    file_count += 1

                    # Update oldest date
                    creation_time = file_stats.st_ctime
                    if oldest_date is None or creation_time < oldest_date:
                        oldest_date = creation_time

        # Convert oldest_date to ISO format if it exists
        oldest_date_iso = None
        if oldest_date is not None:
            from datetime import datetime

            oldest_date_iso = datetime.fromtimestamp(oldest_date).isoformat()

        return jsonify(
            {
                "enabled": True,
                "total_size_mibytes": total_size / 1024 / 1024,
                "file_count": file_count,
                "oldest_file_date": oldest_date_iso,
                "log_directory": LOG_DIR,
            }
        )

    except Exception as e:
        app.logger.error(f"Error getting log directory stats: {str(e)}", exc_info=True)
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/api/purgeCapability", methods=["GET"])
@require_api_key
def get_purge_capability():
    """
    API endpoint to check if previous log purging is allowed.
    Returns a JSON object indicating if purge functionality is available.
    """
    global RETAIN_ALL_POD_LOGS, ALLOW_PREVIOUS_LOG_PURGE

    return jsonify(
        {
            "purge_allowed": RETAIN_ALL_POD_LOGS and ALLOW_PREVIOUS_LOG_PURGE,
            "logs_enabled": RETAIN_ALL_POD_LOGS,
            "purge_enabled": ALLOW_PREVIOUS_LOG_PURGE,
        }
    )


@app.route("/api/purgePreviousLogs", methods=["POST"])
@require_api_key
def purge_previous_logs():
    """
    API endpoint to purge only previous pod log files.
    Returns a JSON object with the number of files deleted and any errors.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS, ALLOW_PREVIOUS_LOG_PURGE

    if not RETAIN_ALL_POD_LOGS:
        return jsonify({"success": False, "message": "Previous pod logs are not enabled."}), 403

    if not ALLOW_PREVIOUS_LOG_PURGE:
        return jsonify({"success": False, "message": "Previous log purging is not allowed."}), 403

    try:
        from log_archiver import purge_previous_pod_logs

        deleted_count, error_count = purge_previous_pod_logs(LOG_DIR, app.logger)

        return jsonify(
            {
                "success": True,
                "deleted_count": deleted_count,
                "error_count": error_count,
                "message": f"Successfully purged {deleted_count} previous pod log files. {error_count} errors occurred.",
            }
        )
    except Exception as e:
        app.logger.error(f"Error purging previous pod logs: {str(e)}", exc_info=True)
        return jsonify({"success": False, "message": f"An unexpected error occurred: {str(e)}"}), 500


@app.route("/api/version", methods=["GET"])
def get_version():
    """
    API endpoint to get the application version.
    Returns a JSON object with the current version.
    """
    return jsonify({"version": __version__})


# --- Events API Endpoints ---
@retry_k8s_operation(max_retries=2, initial_delay=0.3)
def _fetch_events_with_retry(namespace=None):
    """Helper function to fetch events with retry logic."""
    if namespace:
        return v1.list_namespaced_event(namespace=namespace, watch=False, limit=500)
    else:
        return v1.list_event_for_all_namespaces(watch=False, limit=1000)


def fetch_events(namespace: Optional[str] = None) -> List[KubernetesEvent]:
    """Fetch Kubernetes events for the given namespace."""
    try:
        events_list_response = _fetch_events_with_retry(namespace)
        return [KubernetesEvent.from_v1_event(event) for event in events_list_response.items]
    except ApiException as e:
        app.logger.error(f"Error fetching events (Kubernetes API): {e.status} - {e.reason}")
        raise
    except Exception as e:
        app.logger.error(f"Unexpected error fetching events: {e}")
        raise


def filter_events(
    events: List[KubernetesEvent],
    kind_filter: Optional[str] = None,
    type_filter: Optional[str] = None,
    reason_filter: Optional[str] = None,
    search_string: Optional[str] = None,
    case_sensitive: bool = False,
) -> List[KubernetesEvent]:
    """Filter events based on various criteria."""
    filtered_events = events

    if kind_filter:
        filtered_events = [
            e
            for e in filtered_events
            if e.involved_object_kind and kind_filter.lower() in e.involved_object_kind.lower()
        ]

    if type_filter:
        filtered_events = [e for e in filtered_events if e.type and type_filter.lower() in e.type.lower()]

    if reason_filter:
        filtered_events = [e for e in filtered_events if e.reason and reason_filter.lower() in e.reason.lower()]

    if search_string:

        def event_matches_search(event: KubernetesEvent) -> bool:
            searchable_text = " ".join(
                filter(None, [event.message, event.reason, event.involved_object_name, event.involved_object_kind])
            )

            if case_sensitive:
                return search_string in searchable_text
            else:
                return search_string.lower() in searchable_text.lower()

        filtered_events = [e for e in filtered_events if event_matches_search(e)]

    return filtered_events


@app.route("/api/events", methods=["GET"])
@require_api_key
def get_events():
    """
    API endpoint to fetch Kubernetes events.
    Query Parameters:
        - namespace (optional): Specific namespace, defaults to current namespace
        - object_name (optional): Filter by involved object name
        - object_kind (optional): Filter by involved object kind (Pod, Deployment, etc.)
        - event_type (optional): Filter by event type (Normal, Warning)
        - reason (optional): Filter by event reason
        - search_string (optional): Search in event messages and other fields
        - case_sensitive (optional, default 'false'): Case sensitive search
        - sort_order (optional, default 'desc'): 'asc' (oldest first) or 'desc' (newest first)
        - limit (optional, default '100'): Maximum number of events to return
        - exclude_self (optional, default 'false'): Exclude events for current pod
    """
    global KUBE_NAMESPACE, KUBE_POD_NAME

    # Get query parameters
    namespace = request.args.get("namespace", KUBE_NAMESPACE)
    object_name = request.args.get("object_name", "").strip()
    object_kind = request.args.get("object_kind", "").strip()
    event_type = request.args.get("event_type", "").strip()
    reason = request.args.get("reason", "").strip()
    search_string = request.args.get("search_string", "").strip()
    case_sensitive = request.args.get("case_sensitive", "false").lower() == "true"
    sort_order = request.args.get("sort_order", "desc").lower()
    limit_str = request.args.get("limit", "100")
    exclude_self = request.args.get("exclude_self", "false").lower() == "true"

    app.logger.info(
        f"Request for /api/events: namespace='{namespace}', object_name='{object_name}', "
        f"object_kind='{object_kind}', event_type='{event_type}', reason='{reason}', "
        f"search='{search_string}', sort='{sort_order}', limit='{limit_str}', exclude_self='{exclude_self}'"
    )

    try:
        limit = int(limit_str) if limit_str != "0" else None
        if limit is not None and limit < 0:
            return jsonify({"message": "limit must be non-negative or 0."}), 400
    except ValueError:
        return jsonify({"message": "Invalid number for limit."}), 400

    try:
        # Fetch events
        events = fetch_events(namespace)

        # Filter events
        filtered_events = filter_events(
            events,
            kind_filter=object_kind if object_kind else None,
            type_filter=event_type if event_type else None,
            reason_filter=reason if reason else None,
            search_string=search_string if search_string else None,
            case_sensitive=case_sensitive,
        )

        # Additional object name filter
        if object_name:
            filtered_events = [
                e
                for e in filtered_events
                if e.involved_object_name and (object_name.lower() in e.involved_object_name.lower())
            ]

        # Exclude self filter (exclude events for current pod)
        if exclude_self and KUBE_POD_NAME:
            filtered_events = [
                e
                for e in filtered_events
                if not (e.involved_object_kind == "Pod" and e.involved_object_name == KUBE_POD_NAME)
            ]

        # Sort by timestamp
        def get_sort_timestamp(event: KubernetesEvent) -> datetime:
            timestamp = event.last_timestamp or event.first_timestamp
            if timestamp is None:
                return datetime.min.replace(tzinfo=timezone.utc)
            if timestamp.tzinfo is None:
                return timestamp.replace(tzinfo=timezone.utc)
            return timestamp

        filtered_events.sort(key=get_sort_timestamp, reverse=(sort_order == "desc"))

        # Apply limit
        if limit is not None and limit > 0:
            if sort_order == "desc":
                filtered_events = filtered_events[:limit]
            else:
                filtered_events = filtered_events[-limit:]

        # Convert to dict format for JSON response
        events_data = [event.to_dict() for event in filtered_events]

        return jsonify({"events": events_data, "namespace": namespace, "total_count": len(events_data)})

    except ApiException as e:
        app.logger.error(f"Kubernetes API error fetching events: {e.status} - {e.reason} - {e.body}")
        error_message, status_code = format_k8s_error(e)
        return jsonify(
            {
                "message": error_message,
                "error_type": "kubernetes_api_error",
                "retry_suggested": status_code >= 500 or status_code == 429,
            }
        ), status_code
    except Exception as e:
        app.logger.error(f"Unexpected error fetching events: {str(e)}", exc_info=True)
        return jsonify(
            {
                "message": "An unexpected error occurred while fetching events",
                "error_type": "internal_error",
                "retry_suggested": False,
            }
        ), 500


@app.route("/api/event_sources", methods=["GET"])
@require_api_key
def get_event_sources():
    """
    API endpoint to get available event sources (objects that have events).
    Similar to /api/pods but for events.
    Returns unique combinations of object kinds and names that have events.
    """
    global KUBE_NAMESPACE

    namespace = request.args.get("namespace", KUBE_NAMESPACE)

    try:
        app.logger.info(f"Fetching events for namespace: {namespace}")
        events = fetch_events(namespace)
        app.logger.info(f"Retrieved {len(events)} events")

        # Create unique sources from events
        sources = {}  # key: "kind/name", value: {kind, name, event_count, latest_timestamp, latest_type}

        for event in events:
            try:
                if not event.involved_object_kind or not event.involved_object_name:
                    continue

                key = f"{event.involved_object_kind}/{event.involved_object_name}"

                if key not in sources:
                    sources[key] = {
                        "id": key,
                        "object_kind": event.involved_object_kind,
                        "object_name": event.involved_object_name,
                        "event_count": 0,
                        "latest_timestamp": None,
                        "latest_event_type": None,
                        "namespace": event.namespace,
                    }

                sources[key]["event_count"] += 1

                # Update latest timestamp
                event_timestamp = event.last_timestamp or event.first_timestamp
                if event_timestamp:
                    # Convert to datetime for comparison if latest_timestamp is a string
                    latest_ts = sources[key]["latest_timestamp"]
                    if latest_ts is None:
                        should_update = True
                    elif isinstance(latest_ts, str):
                        # Convert ISO string back to datetime for comparison
                        try:
                            # Handle different ISO format variations
                            if latest_ts.endswith('Z'):
                                latest_ts_clean = latest_ts.replace('Z', '+00:00')
                            elif '+' in latest_ts or latest_ts.endswith('UTC'):
                                latest_ts_clean = latest_ts
                            else:
                                latest_ts_clean = latest_ts + '+00:00'

                            latest_dt = datetime.fromisoformat(latest_ts_clean)

                            # Ensure both timestamps are timezone-aware for comparison
                            if event_timestamp.tzinfo is None:
                                event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)
                            if latest_dt.tzinfo is None:
                                latest_dt = latest_dt.replace(tzinfo=timezone.utc)

                            should_update = event_timestamp > latest_dt
                        except (ValueError, AttributeError) as e:
                            app.logger.debug(f"Error parsing timestamp {latest_ts}: {e}")
                            should_update = True
                    else:
                        should_update = event_timestamp > latest_ts

                    if should_update:
                        sources[key]["latest_timestamp"] = event_timestamp.isoformat()
                        sources[key]["latest_event_type"] = event.type
            except Exception as e:
                app.logger.warning(f"Error processing event for object {event.involved_object_kind}/{event.involved_object_name}: {e}")
                continue

        # Convert to list and sort by latest timestamp
        sources_list = list(sources.values())
        sources_list.sort(key=lambda x: x["latest_timestamp"] or "0000-00-00T00:00:00Z", reverse=True)

        app.logger.info(f"Processed {len(sources_list)} unique event sources")
        return jsonify({"sources": sources_list, "namespace": namespace})

    except ApiException as e:
        app.logger.error(f"Kubernetes API error fetching event sources: {e.status} - {e.reason}")
        error_message, status_code = format_k8s_error(e)
        return jsonify(
            {
                "message": error_message,
                "error_type": "kubernetes_api_error",
                "retry_suggested": status_code >= 500 or status_code == 429,
            }
        ), status_code
    except Exception as e:
        app.logger.error(f"Unexpected error fetching event sources: {str(e)}", exc_info=True)
        return jsonify(
            {
                "message": "An unexpected error occurred while fetching event sources",
                "error_type": "internal_error",
                "retry_suggested": False,
            }
        ), 500


@app.route("/api/download_log", methods=["GET"])
@require_api_key
def download_log():
    """
    API endpoint to download a specific log file.
    Query Parameters:
        - pod_name (required): The name of the pod/container (format: 'pod/container').
        - source (optional, default 'archived'): 'current' for current logs, 'archived' for archived logs.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS, KUBE_NAMESPACE, v1

    pod_name = request.args.get("pod_name")
    source = request.args.get("source", "archived").lower()

    if not pod_name:
        return jsonify({"message": "Pod name is required"}), 400

    try:
        if source == "current":
            # Download current logs
            pod_name_parts = pod_name.split("/", 1) if "/" in pod_name else [pod_name, None]
            actual_pod_name = pod_name_parts[0]
            container_name = pod_name_parts[1]

            # Handle init container naming
            if container_name and container_name.startswith("init-"):
                actual_container_name = container_name[5:]
            else:
                actual_container_name = container_name

            # Fetch logs from Kubernetes
            log_data = v1.read_namespaced_pod_log(
                name=actual_pod_name,
                namespace=KUBE_NAMESPACE,
                container=actual_container_name,
                timestamps=True,
                follow=False,
                _preload_content=True,
            )

            # Create a temporary file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as temp_file:
                temp_file.write(log_data)
                temp_file_path = temp_file.name

            # Send the file and clean up
            filename = f"{pod_name.replace('/', '_')}_current.log"
            return send_file(temp_file_path, as_attachment=True, download_name=filename, mimetype="text/plain")

        elif source == "archived":
            # Download archived logs
            if not RETAIN_ALL_POD_LOGS:
                return jsonify({"message": "Archived logs are not enabled"}), 403

            log_file_path = os.path.join(LOG_DIR, f"{pod_name}.log")

            if not os.path.exists(log_file_path):
                return jsonify({"message": f"Archived log for {pod_name} not found"}), 404

            filename = f"{pod_name.replace('/', '_')}_archived.log"
            return send_file(log_file_path, as_attachment=True, download_name=filename, mimetype="text/plain")
        else:
            return jsonify({"message": "Invalid source. Use 'current' or 'archived'"}), 400

    except ApiException as e:
        app.logger.error(f"Kubernetes API error downloading logs for '{pod_name}': {e.status} - {e.reason}")
        error_message, status_code = format_k8s_error(e)
        return jsonify({"message": error_message}), status_code
    except Exception as e:
        app.logger.error(f"Error downloading log for '{pod_name}': {str(e)}", exc_info=True)
        return jsonify({"message": f"Error downloading log: {str(e)}"}), 500


@app.route("/api/download_pod_logs", methods=["GET"])
@require_api_key
def download_pod_logs():
    """
    API endpoint to download all logs for a specific pod as a zip file.
    Query Parameters:
        - pod_name (required): The name of the pod.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS

    pod_name = request.args.get("pod_name")

    if not pod_name:
        return jsonify({"message": "Pod name is required"}), 400

    if not RETAIN_ALL_POD_LOGS:
        return jsonify({"message": "Archived logs are not enabled"}), 403

    if not os.path.exists(LOG_DIR):
        return jsonify({"message": "Log directory does not exist"}), 404

    try:
        # Create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_zip:
            temp_zip_path = temp_zip.name

        # Create the zip file
        with zipfile.ZipFile(temp_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the log directory and add all .log files for the specific pod
            for root, _, files in os.walk(LOG_DIR):
                for filename in files:
                    if filename.endswith(".log"):
                        file_path = os.path.join(root, filename)
                        # Get relative path from LOG_DIR
                        relative_path = os.path.relpath(file_path, LOG_DIR)

                        # Check if this file belongs to the specified pod
                        # Files are either "pod/container.log" or "pod.log"
                        if relative_path.startswith(f"{pod_name}/") or relative_path == f"{pod_name}.log":
                            zipf.write(file_path, relative_path)

        # Check if any files were added to the zip
        with zipfile.ZipFile(temp_zip_path, "r") as zipf:
            if len(zipf.namelist()) == 0:
                os.unlink(temp_zip_path)
                return jsonify({"message": f"No logs found for pod {pod_name}"}), 404

        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logpilot_{pod_name}_logs_{timestamp}.zip"

        return send_file(temp_zip_path, as_attachment=True, download_name=filename, mimetype="application/zip")

    except Exception as e:
        app.logger.error(f"Error creating pod log archive for {pod_name}: {str(e)}", exc_info=True)
        return jsonify({"message": f"Error creating pod log archive: {str(e)}"}), 500


@app.route("/api/download_all_logs", methods=["GET"])
@require_api_key
def download_all_logs():
    """
    API endpoint to download all archived logs as a zip file.
    Only available if RETAIN_ALL_POD_LOGS is enabled.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS

    if not RETAIN_ALL_POD_LOGS:
        return jsonify({"message": "Archived logs are not enabled"}), 403

    if not os.path.exists(LOG_DIR):
        return jsonify({"message": "Log directory does not exist"}), 404

    try:
        # Create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_zip:
            temp_zip_path = temp_zip.name

        # Create the zip file
        with zipfile.ZipFile(temp_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the log directory and add all .log files
            for root, _, files in os.walk(LOG_DIR):
                for filename in files:
                    if filename.endswith(".log"):
                        file_path = os.path.join(root, filename)
                        # Get relative path from LOG_DIR for the zip archive
                        arcname = os.path.relpath(file_path, LOG_DIR)
                        zipf.write(file_path, arcname)

        # Get stats for the filename
        total_size, file_count, _ = get_log_dir_stats(LOG_DIR)
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logpilot_logs_{file_count}files_{timestamp}.zip"

        return send_file(temp_zip_path, as_attachment=True, download_name=filename, mimetype="application/zip")

    except Exception as e:
        app.logger.error(f"Error creating log archive: {str(e)}", exc_info=True)
        return jsonify({"message": f"Error creating log archive: {str(e)}"}), 500


# --- Events API Endpoints ---
@retry_k8s_operation(max_retries=2, initial_delay=0.3)
def _fetch_events_with_retry(namespace=None):
    """Helper function to fetch events with retry logic."""
    if namespace:
        return v1.list_namespaced_event(namespace=namespace, watch=False, limit=500)
    else:
        return v1.list_event_for_all_namespaces(watch=False, limit=1000)


def fetch_events(namespace: Optional[str] = None) -> List[KubernetesEvent]:
    """Fetch Kubernetes events for the given namespace."""
    try:
        events_list_response = _fetch_events_with_retry(namespace)
        return [KubernetesEvent.from_v1_event(event) for event in events_list_response.items]
    except ApiException as e:
        app.logger.error(f"Error fetching events (Kubernetes API): {e.status} - {e.reason}")
        raise
    except Exception as e:
        app.logger.error(f"Unexpected error fetching events: {e}")
        raise


def filter_events(
    events: List[KubernetesEvent],
    kind_filter: Optional[str] = None,
    type_filter: Optional[str] = None,
    reason_filter: Optional[str] = None,
    search_string: Optional[str] = None,
    case_sensitive: bool = False,
) -> List[KubernetesEvent]:
    """Filter events based on various criteria."""
    filtered_events = events

    if kind_filter:
        filtered_events = [
            e
            for e in filtered_events
            if e.involved_object_kind and kind_filter.lower() in e.involved_object_kind.lower()
        ]

    if type_filter:
        filtered_events = [e for e in filtered_events if e.type and type_filter.lower() in e.type.lower()]

    if reason_filter:
        filtered_events = [e for e in filtered_events if e.reason and reason_filter.lower() in e.reason.lower()]

    if search_string:

        def event_matches_search(event: KubernetesEvent) -> bool:
            searchable_text = " ".join(
                filter(None, [event.message, event.reason, event.involved_object_name, event.involved_object_kind])
            )

            if case_sensitive:
                return search_string in searchable_text
            else:
                return search_string.lower() in searchable_text.lower()

        filtered_events = [e for e in filtered_events if event_matches_search(e)]

    return filtered_events


@app.route("/api/events", methods=["GET"])
@require_api_key
def get_events():
    """
    API endpoint to fetch Kubernetes events.
    Query Parameters:
        - namespace (optional): Specific namespace, defaults to current namespace
        - object_name (optional): Filter by involved object name
        - object_kind (optional): Filter by involved object kind (Pod, Deployment, etc.)
        - event_type (optional): Filter by event type (Normal, Warning)
        - reason (optional): Filter by event reason
        - search_string (optional): Search in event messages and other fields
        - case_sensitive (optional, default 'false'): Case sensitive search
        - sort_order (optional, default 'desc'): 'asc' (oldest first) or 'desc' (newest first)
        - limit (optional, default '100'): Maximum number of events to return
        - exclude_self (optional, default 'false'): Exclude events for current pod
    """
    global KUBE_NAMESPACE, KUBE_POD_NAME

    # Get query parameters
    namespace = request.args.get("namespace", KUBE_NAMESPACE)
    object_name = request.args.get("object_name", "").strip()
    object_kind = request.args.get("object_kind", "").strip()
    event_type = request.args.get("event_type", "").strip()
    reason = request.args.get("reason", "").strip()
    search_string = request.args.get("search_string", "").strip()
    case_sensitive = request.args.get("case_sensitive", "false").lower() == "true"
    sort_order = request.args.get("sort_order", "desc").lower()
    limit_str = request.args.get("limit", "100")
    exclude_self = request.args.get("exclude_self", "false").lower() == "true"

    app.logger.info(
        f"Request for /api/events: namespace='{namespace}', object_name='{object_name}', "
        f"object_kind='{object_kind}', event_type='{event_type}', reason='{reason}', "
        f"search='{search_string}', sort='{sort_order}', limit='{limit_str}', exclude_self='{exclude_self}'"
    )

    try:
        limit = int(limit_str) if limit_str != "0" else None
        if limit is not None and limit < 0:
            return jsonify({"message": "limit must be non-negative or 0."}), 400
    except ValueError:
        return jsonify({"message": "Invalid number for limit."}), 400

    try:
        # Fetch events
        events = fetch_events(namespace)

        # Filter events
        filtered_events = filter_events(
            events,
            kind_filter=object_kind if object_kind else None,
            type_filter=event_type if event_type else None,
            reason_filter=reason if reason else None,
            search_string=search_string if search_string else None,
            case_sensitive=case_sensitive,
        )

        # Additional object name filter
        if object_name:
            filtered_events = [
                e
                for e in filtered_events
                if e.involved_object_name and (object_name.lower() in e.involved_object_name.lower())
            ]

        # Exclude self filter (exclude events for current pod)
        if exclude_self and KUBE_POD_NAME:
            filtered_events = [
                e
                for e in filtered_events
                if not (e.involved_object_kind == "Pod" and e.involved_object_name == KUBE_POD_NAME)
            ]

        # Sort by timestamp
        def get_sort_timestamp(event: KubernetesEvent) -> datetime:
            timestamp = event.last_timestamp or event.first_timestamp
            if timestamp is None:
                return datetime.min.replace(tzinfo=timezone.utc)
            if timestamp.tzinfo is None:
                return timestamp.replace(tzinfo=timezone.utc)
            return timestamp

        filtered_events.sort(key=get_sort_timestamp, reverse=(sort_order == "desc"))

        # Apply limit
        if limit is not None and limit > 0:
            if sort_order == "desc":
                filtered_events = filtered_events[:limit]
            else:
                filtered_events = filtered_events[-limit:]

        # Convert to dict format for JSON response
        events_data = [event.to_dict() for event in filtered_events]

        return jsonify({"events": events_data, "namespace": namespace, "total_count": len(events_data)})

    except ApiException as e:
        app.logger.error(f"Kubernetes API error fetching events: {e.status} - {e.reason} - {e.body}")
        error_message, status_code = format_k8s_error(e)
        return jsonify(
            {
                "message": error_message,
                "error_type": "kubernetes_api_error",
                "retry_suggested": status_code >= 500 or status_code == 429,
            }
        ), status_code
    except Exception as e:
        app.logger.error(f"Unexpected error fetching events: {str(e)}", exc_info=True)
        return jsonify(
            {
                "message": "An unexpected error occurred while fetching events",
                "error_type": "internal_error",
                "retry_suggested": False,
            }
        ), 500


@app.route("/api/event_sources", methods=["GET"])
@require_api_key
def get_event_sources():
    """
    API endpoint to get available event sources (objects that have events).
    Similar to /api/pods but for events.
    Returns unique combinations of object kinds and names that have events.
    """
    global KUBE_NAMESPACE

    namespace = request.args.get("namespace", KUBE_NAMESPACE)

    try:
        app.logger.info(f"Fetching events for namespace: {namespace}")
        events = fetch_events(namespace)
        app.logger.info(f"Retrieved {len(events)} events")

        # Create unique sources from events
        sources = {}  # key: "kind/name", value: {kind, name, event_count, latest_timestamp, latest_type}

        for event in events:
            try:
                if not event.involved_object_kind or not event.involved_object_name:
                    continue

                key = f"{event.involved_object_kind}/{event.involved_object_name}"

                if key not in sources:
                    sources[key] = {
                        "id": key,
                        "object_kind": event.involved_object_kind,
                        "object_name": event.involved_object_name,
                        "event_count": 0,
                        "latest_timestamp": None,
                        "latest_event_type": None,
                        "namespace": event.namespace,
                    }

                sources[key]["event_count"] += 1

                # Update latest timestamp
                event_timestamp = event.last_timestamp or event.first_timestamp
                if event_timestamp:
                    # Convert to datetime for comparison if latest_timestamp is a string
                    latest_ts = sources[key]["latest_timestamp"]
                    if latest_ts is None:
                        should_update = True
                    elif isinstance(latest_ts, str):
                        # Convert ISO string back to datetime for comparison
                        try:
                            # Handle different ISO format variations
                            if latest_ts.endswith('Z'):
                                latest_ts_clean = latest_ts.replace('Z', '+00:00')
                            elif '+' in latest_ts or latest_ts.endswith('UTC'):
                                latest_ts_clean = latest_ts
                            else:
                                latest_ts_clean = latest_ts + '+00:00'

                            latest_dt = datetime.fromisoformat(latest_ts_clean)

                            # Ensure both timestamps are timezone-aware for comparison
                            if event_timestamp.tzinfo is None:
                                event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)
                            if latest_dt.tzinfo is None:
                                latest_dt = latest_dt.replace(tzinfo=timezone.utc)

                            should_update = event_timestamp > latest_dt
                        except (ValueError, AttributeError) as e:
                            app.logger.debug(f"Error parsing timestamp {latest_ts}: {e}")
                            should_update = True
                    else:
                        should_update = event_timestamp > latest_ts

                    if should_update:
                        sources[key]["latest_timestamp"] = event_timestamp.isoformat()
                        sources[key]["latest_event_type"] = event.type
            except Exception as e:
                app.logger.warning(f"Error processing event for object {event.involved_object_kind}/{event.involved_object_name}: {e}")
                continue

        # Convert to list and sort by latest timestamp
        sources_list = list(sources.values())
        sources_list.sort(key=lambda x: x["latest_timestamp"] or "0000-00-00T00:00:00Z", reverse=True)

        app.logger.info(f"Processed {len(sources_list)} unique event sources")
        return jsonify({"sources": sources_list, "namespace": namespace})

    except ApiException as e:
        app.logger.error(f"Kubernetes API error fetching event sources: {e.status} - {e.reason}")
        error_message, status_code = format_k8s_error(e)
        return jsonify(
            {
                "message": error_message,
                "error_type": "kubernetes_api_error",
                "retry_suggested": status_code >= 500 or status_code == 429,
            }
        ), status_code
    except Exception as e:
        app.logger.error(f"Unexpected error fetching event sources: {str(e)}", exc_info=True)
        return jsonify(
            {
                "message": "An unexpected error occurred while fetching event sources",
                "error_type": "internal_error",
                "retry_suggested": False,
            }
        ), 500


@app.route("/api/download_log", methods=["GET"])
@require_api_key
def download_log():
    """
    API endpoint to download a specific log file.
    Query Parameters:
        - pod_name (required): The name of the pod/container (format: 'pod/container').
        - source (optional, default 'archived'): 'current' for current logs, 'archived' for archived logs.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS, KUBE_NAMESPACE, v1

    pod_name = request.args.get("pod_name")
    source = request.args.get("source", "archived").lower()

    if not pod_name:
        return jsonify({"message": "Pod name is required"}), 400

    try:
        if source == "current":
            # Download current logs
            pod_name_parts = pod_name.split("/", 1) if "/" in pod_name else [pod_name, None]
            actual_pod_name = pod_name_parts[0]
            container_name = pod_name_parts[1]

            # Handle init container naming
            if container_name and container_name.startswith("init-"):
                actual_container_name = container_name[5:]
            else:
                actual_container_name = container_name

            # Fetch logs from Kubernetes
            log_data = v1.read_namespaced_pod_log(
                name=actual_pod_name,
                namespace=KUBE_NAMESPACE,
                container=actual_container_name,
                timestamps=True,
                follow=False,
                _preload_content=True,
            )

            # Create a temporary file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as temp_file:
                temp_file.write(log_data)
                temp_file_path = temp_file.name

            # Send the file and clean up
            filename = f"{pod_name.replace('/', '_')}_current.log"
            return send_file(temp_file_path, as_attachment=True, download_name=filename, mimetype="text/plain")

        elif source == "archived":
            # Download archived logs
            if not RETAIN_ALL_POD_LOGS:
                return jsonify({"message": "Archived logs are not enabled"}), 403

            log_file_path = os.path.join(LOG_DIR, f"{pod_name}.log")

            if not os.path.exists(log_file_path):
                return jsonify({"message": f"Archived log for {pod_name} not found"}), 404

            filename = f"{pod_name.replace('/', '_')}_archived.log"
            return send_file(log_file_path, as_attachment=True, download_name=filename, mimetype="text/plain")
        else:
            return jsonify({"message": "Invalid source. Use 'current' or 'archived'"}), 400

    except ApiException as e:
        app.logger.error(f"Kubernetes API error downloading logs for '{pod_name}': {e.status} - {e.reason}")
        error_message, status_code = format_k8s_error(e)
        return jsonify({"message": error_message}), status_code
    except Exception as e:
        app.logger.error(f"Error downloading log for '{pod_name}': {str(e)}", exc_info=True)
        return jsonify({"message": f"Error downloading log: {str(e)}"}), 500


@app.route("/api/download_pod_logs", methods=["GET"])
@require_api_key
def download_pod_logs():
    """
    API endpoint to download all logs for a specific pod as a zip file.
    Query Parameters:
        - pod_name (required): The name of the pod.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS

    pod_name = request.args.get("pod_name")

    if not pod_name:
        return jsonify({"message": "Pod name is required"}), 400

    if not RETAIN_ALL_POD_LOGS:
        return jsonify({"message": "Archived logs are not enabled"}), 403

    if not os.path.exists(LOG_DIR):
        return jsonify({"message": "Log directory does not exist"}), 404

    try:
        # Create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_zip:
            temp_zip_path = temp_zip.name

        # Create the zip file
        with zipfile.ZipFile(temp_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the log directory and add all .log files for the specific pod
            for root, _, files in os.walk(LOG_DIR):
                for filename in files:
                    if filename.endswith(".log"):
                        file_path = os.path.join(root, filename)
                        # Get relative path from LOG_DIR
                        relative_path = os.path.relpath(file_path, LOG_DIR)

                        # Check if this file belongs to the specified pod
                        # Files are either "pod/container.log" or "pod.log"
                        if relative_path.startswith(f"{pod_name}/") or relative_path == f"{pod_name}.log":
                            zipf.write(file_path, relative_path)

        # Check if any files were added to the zip
        with zipfile.ZipFile(temp_zip_path, "r") as zipf:
            if len(zipf.namelist()) == 0:
                os.unlink(temp_zip_path)
                return jsonify({"message": f"No logs found for pod {pod_name}"}), 404

        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logpilot_{pod_name}_logs_{timestamp}.zip"

        return send_file(temp_zip_path, as_attachment=True, download_name=filename, mimetype="application/zip")

    except Exception as e:
        app.logger.error(f"Error creating pod log archive for {pod_name}: {str(e)}", exc_info=True)
        return jsonify({"message": f"Error creating pod log archive: {str(e)}"}), 500


@app.route("/api/download_all_logs", methods=["GET"])
@require_api_key
def download_all_logs():
    """
    API endpoint to download all archived logs as a zip file.
    Only available if RETAIN_ALL_POD_LOGS is enabled.
    """
    global LOG_DIR, RETAIN_ALL_POD_LOGS

    if not RETAIN_ALL_POD_LOGS:
        return jsonify({"message": "Archived logs are not enabled"}), 403

    if not os.path.exists(LOG_DIR):
        return jsonify({"message": "Log directory does not exist"}), 404

    try:
        # Create a temporary zip file
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_zip:
            temp_zip_path = temp_zip.name

        # Create the zip file
        with zipfile.ZipFile(temp_zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the log directory and add all .log files
            for root, _, files in os.walk(LOG_DIR):
                for filename in files:
                    if filename.endswith(".log"):
                        file_path = os.path.join(root, filename)
                        # Get relative path from LOG_DIR for the zip archive
                        arcname = os.path.relpath(file_path, LOG_DIR)
                        zipf.write(file_path, arcname)

        # Get stats for the filename
        total_size, file_count, _ = get_log_dir_stats(LOG_DIR)
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logpilot_logs_{file_count}files_{timestamp}.zip"

        return send_file(temp_zip_path, as_attachment=True, download_name=filename, mimetype="application/zip")

    except Exception as e:
        app.logger.error(f"Error creating log archive: {str(e)}", exc_info=True)
        return jsonify({"message": f"Error creating log archive: {str(e)}"}), 500


# --- Main Execution ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
