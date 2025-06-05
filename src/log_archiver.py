import os
import time
from datetime import datetime, timedelta, timezone
import threading
from kubernetes import watch
from kubernetes.client.rest import ApiException
import logging
from kubernetes import client


def delete_old_logs(log_dir, max_age_minutes, logger):
    """
    Deletes log files in the specified directory older than max_age_minutes.
    """
    if not os.path.exists(log_dir):
        logger.warning(f"Log directory {log_dir} does not exist. Skipping cleanup.")
        return

    logger.info(f"Starting cleanup of logs older than {max_age_minutes} minutes in {log_dir}...")
    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
    deleted_count = 0
    error_count = 0

    for filename in os.listdir(log_dir):
        if filename.endswith(".log"):  # Process only .log files
            file_path = os.path.join(log_dir, filename)
            try:
                file_mod_time_timestamp = os.path.getmtime(file_path)
                file_mod_time = datetime.fromtimestamp(file_mod_time_timestamp, timezone.utc)

                if file_mod_time < cutoff_time:
                    os.remove(file_path)
                    logger.info(f"Deleted old log file: {file_path} (modified {file_mod_time})")
                    deleted_count += 1
            except OSError as e:
                logger.error(f"Error deleting file {file_path}: {e}")
                error_count += 1
            except Exception as e:
                logger.error(f"Unexpected error processing file {file_path}: {e}")
                error_count += 1
    logger.info(f"Log cleanup finished. Deleted: {deleted_count}, Errors: {error_count}")


def start_log_cleanup_job(log_dir, max_age_minutes, logger, interval_minutes=10):
    """
    Starts a periodic job to delete old logs.
    Runs in a daemon thread so it doesn't block application exit.
    """
    logger.info(f"Initializing log cleanup job. Will run every {interval_minutes} minutes.")

    def job():
        while True:
            try:
                delete_old_logs(log_dir, max_age_minutes, logger)
            except Exception as e:
                logger.error(f"Unhandled exception in log cleanup job: {e}", exc_info=True)
            time.sleep(interval_minutes * 60)

    thread = threading.Thread(target=job, daemon=True)
    thread.name = "LogCleanupThread"
    thread.start()
    logger.info("Log cleanup job thread started.")


# --- Log Archival Functions ---

# Dictionary to keep track of active log archival threads and their stop events
# Key: pod_name, Value: {"thread": threading.Thread, "stop_event": threading.Event}
active_archivals = {}
archival_lock = threading.Lock()  # To protect access to active_archivals


def get_pod_logs(v1, namespace, pod_name, container_name=None):
    """
    Fetch logs for a specific pod and container.
    Returns the raw log data as a string.
    """
    try:
        return v1.read_namespaced_pod_log(
            name=pod_name,
            namespace=namespace,
            container=container_name,
            timestamps=True,
            follow=False,
            _preload_content=True,
        )
    except ApiException as e:
        logging.error(f"Error fetching logs for pod {pod_name} container {container_name}: {e}")
        return None


def archive_pod_logs(v1, namespace, pod_name, log_dir):
    """
    Archive logs for all containers in a pod.
    """
    try:
        pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        for container in pod.spec.containers:
            container_name = container.name
            log_data = get_pod_logs(v1, namespace, pod_name, container_name)
            if log_data:
                # Create filename based on whether there are multiple containers
                if len(pod.spec.containers) > 1:
                    filename = f"{pod_name}/{container_name}.log"
                else:
                    filename = f"{pod_name}.log"
                    
                log_path = os.path.join(log_dir, filename)
                os.makedirs(os.path.dirname(log_path), exist_ok=True)
                
                with open(log_path, "w") as f:
                    f.write(log_data)
                logging.info(f"Archived logs for pod {pod_name} container {container_name}")
    except ApiException as e:
        logging.error(f"Error archiving logs for pod {pod_name}: {e}")


def watch_pods_and_archive(namespace, v1, log_dir, logger):
    """
    Watch for pod changes and archive logs when pods are terminated.
    """
    logger.info(f"Starting pod watcher for namespace {namespace}")
    
    while True:
        try:
            # Get all pods in the namespace
            pod_list = v1.list_namespaced_pod(namespace=namespace)
            
            # Archive logs for each pod
            for pod in pod_list.items:
                if pod.metadata.name != os.environ.get("K8S_POD_NAME", "NOT-SET"):
                    archive_pod_logs(v1, namespace, pod.metadata.name, log_dir)
            
            # Sleep for a while before checking again
            time.sleep(60)  # Check every minute
            
        except Exception as e:
            logger.error(f"Error in pod watcher: {e}")
            time.sleep(60)  # Wait before retrying


# Placeholder for the main function in app.py to start this watcher
# def start_pod_log_archival_watcher(namespace, v1_api, log_dir, logger):
#     if RETAIN_ALL_POD_LOGS_FROM_APP_CONTEXT:
#         thread = threading.Thread(
#             target=watch_pods_and_archive,
#             args=(namespace, v1_api, log_dir, logger),
#             daemon=True
#         )
#         thread.name = "PodLogArchiverMainWatcher"
#         thread.start()
#         logger.info("Pod log archival watcher thread started.")
