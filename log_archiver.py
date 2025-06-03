import os
import time
from datetime import datetime, timedelta, timezone
import threading
from kubernetes import watch
from kubernetes.client.rest import ApiException


def delete_old_logs(log_dir, max_age_minutes, logger):
    """
    Deletes log files in the specified directory older than max_age_minutes.
    """
    if not os.path.exists(log_dir):
        logger.warning(f"Log directory {log_dir} does not exist. Skipping cleanup.")
        return

    logger.info(
        f"Starting cleanup of logs older than {max_age_minutes} minutes in {log_dir}..."
    )
    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
    deleted_count = 0
    error_count = 0

    for filename in os.listdir(log_dir):
        if filename.endswith(".log"):  # Process only .log files
            file_path = os.path.join(log_dir, filename)
            try:
                file_mod_time_timestamp = os.path.getmtime(file_path)
                file_mod_time = datetime.fromtimestamp(
                    file_mod_time_timestamp, timezone.utc
                )

                if file_mod_time < cutoff_time:
                    os.remove(file_path)
                    logger.info(
                        f"Deleted old log file: {file_path} (modified {file_mod_time})"
                    )
                    deleted_count += 1
            except OSError as e:
                logger.error(f"Error deleting file {file_path}: {e}")
                error_count += 1
            except Exception as e:
                logger.error(f"Unexpected error processing file {file_path}: {e}")
                error_count += 1
    logger.info(
        f"Log cleanup finished. Deleted: {deleted_count}, Errors: {error_count}"
    )


def start_log_cleanup_job(log_dir, max_age_minutes, logger, interval_minutes=10):
    """
    Starts a periodic job to delete old logs.
    Runs in a daemon thread so it doesn't block application exit.
    """
    logger.info(
        f"Initializing log cleanup job. Will run every {interval_minutes} minutes."
    )

    def job():
        while True:
            try:
                delete_old_logs(log_dir, max_age_minutes, logger)
            except Exception as e:
                logger.error(
                    f"Unhandled exception in log cleanup job: {e}", exc_info=True
                )
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


def archive_pod_logs(pod_name, namespace, v1_api, log_dir, logger, stop_event):
    """
    Streams logs from a specific pod and saves them to a file in log_dir.
    Stops when stop_event is set.
    """
    log_file_path = os.path.join(log_dir, f"{pod_name}.log")
    logger.info(f"Starting log archival for pod {pod_name} to {log_file_path}")

    try:
        with open(log_file_path, "a", encoding="utf-8") as log_file:
            # Get existing log size to potentially seek past it if K8s API allows 'since_seconds' accurately
            # For simplicity now, we append. If the pod restarts with the same name, logs will be appended.
            # A more robust solution might handle log rotation or use 'since_time'.

            log_stream = v1_api.read_namespaced_pod_log(
                name=pod_name,
                namespace=namespace,
                timestamps=True,
                follow=True,
                _preload_content=False,  # Important for streaming
                # since_seconds=1 # Optionally, to avoid re-fetching all past logs if connection drops
            )

            for log_line_bytes in log_stream:
                if stop_event.is_set():
                    logger.info(
                        f"Stop event received for pod {pod_name}. Stopping archival."
                    )
                    break

                log_line = log_line_bytes.decode("utf-8", errors="replace").strip()
                if log_line:
                    log_file.write(log_line + "\n")
                    log_file.flush()  # Ensure logs are written immediately
                else:
                    # K8s keep-alive might send empty lines. Add a small sleep to prevent busy-looping on disconnects.
                    # time.sleep(0.1) # Re-evaluate if needed based on K8s client behavior
                    pass

    except ApiException as e:
        if e.status == 404:
            logger.warning(
                f"Pod {pod_name} not found during log archival (possibly deleted): {e.reason}"
            )
        else:
            logger.error(
                f"Kubernetes API error archiving logs for {pod_name}: {e.status} - {e.reason}",
                exc_info=True,
            )
    except Exception as e:
        logger.error(
            f"Unexpected error archiving logs for pod {pod_name}: {e}", exc_info=True
        )
    finally:
        logger.info(f"Log archival ended for pod {pod_name}.")
        # Clean up from active_archivals should be handled by the watcher


def watch_pods_and_archive(namespace, v1_api, log_dir, logger):
    """
    Watches for pod creation and deletion in the namespace to start/stop log archival.
    This function is intended to be run in a background thread.
    """
    logger.info(
        f"Starting pod watcher for namespace '{namespace}' to archive logs to '{log_dir}'."
    )
    w = watch.Watch()

    while True:  # Loop to allow restarting watch on errors
        try:
            logger.info(f"Watching for pod events in namespace '{namespace}'...")
            for event in w.stream(
                v1_api.list_namespaced_pod, namespace=namespace, timeout_seconds=60
            ):
                pod = event["object"]
                pod_name = pod.metadata.name
                event_type = event["type"]  # ADDED, MODIFIED, DELETED

                with archival_lock:
                    if event_type == "ADDED":
                        if (
                            pod.status.phase == "Running"
                            and pod_name not in active_archivals
                        ):
                            logger.info(
                                f"Pod {pod_name} is Running. Starting log archival."
                            )
                            stop_event = threading.Event()
                            thread = threading.Thread(
                                target=archive_pod_logs,
                                args=(
                                    pod_name,
                                    namespace,
                                    v1_api,
                                    log_dir,
                                    logger,
                                    stop_event,
                                ),
                                daemon=True,
                            )
                            thread.name = f"LogArchive-{pod_name}"
                            active_archivals[pod_name] = {
                                "thread": thread,
                                "stop_event": stop_event,
                            }
                            thread.start()
                        elif pod_name in active_archivals:
                            logger.debug(
                                f"Pod {pod_name} ADDED event, but already tracking. Phase: {pod.status.phase}"
                            )
                        else:
                            logger.debug(
                                f"Pod {pod_name} ADDED event, but not Running. Phase: {pod.status.phase}. Will not archive yet."
                            )

                    elif event_type == "MODIFIED":
                        # If a pod transitions to Running and we are not archiving it yet.
                        if (
                            pod.status.phase == "Running"
                            and pod_name not in active_archivals
                        ):
                            logger.info(
                                f"Pod {pod_name} transitioned to Running. Starting log archival."
                            )
                            stop_event = threading.Event()
                            thread = threading.Thread(
                                target=archive_pod_logs,
                                args=(
                                    pod_name,
                                    namespace,
                                    v1_api,
                                    log_dir,
                                    logger,
                                    stop_event,
                                ),
                                daemon=True,
                            )
                            thread.name = f"LogArchive-{pod_name}"
                            active_archivals[pod_name] = {
                                "thread": thread,
                                "stop_event": stop_event,
                            }
                            thread.start()
                        # If a pod is no longer running (e.g., Succeeded, Failed) and we were archiving.
                        elif (
                            pod.status.phase not in ["Running", "Pending"]
                            and pod_name in active_archivals
                        ):
                            logger.info(
                                f"Pod {pod_name} is no longer Running (phase: {pod.status.phase}). Stopping log archival."
                            )
                            archival_info = active_archivals.pop(pod_name)
                            archival_info["stop_event"].set()
                            # archival_info["thread"].join(timeout=10) # Wait for thread to finish
                            # logger.info(f"Log archival thread for {pod_name} joined.")

                    elif event_type == "DELETED":
                        if pod_name in active_archivals:
                            logger.info(
                                f"Pod {pod_name} DELETED. Stopping log archival."
                            )
                            archival_info = active_archivals.pop(pod_name)
                            archival_info["stop_event"].set()
                            # archival_info["thread"].join(timeout=10) # Wait for thread to finish
                            # logger.info(f"Log archival thread for {pod_name} joined.")
                        else:
                            logger.info(
                                f"Pod {pod_name} DELETED event, but was not being actively archived."
                            )
            logger.debug("Watch stream timeout or ended, will restart.")

        except ApiException as e:
            if e.status == 410:  # Gone, resource version too old
                logger.warning(
                    "Kubernetes watch API error: Resource version too old (410 Gone). Restarting watch."
                )
                # Reset resource_version for the w.stream call if possible, or just let it restart
            else:
                logger.error(
                    f"Kubernetes API error during pod watch: {e.status} - {e.reason}. Retrying in 30s.",
                    exc_info=True,
                )
                time.sleep(30)
        except Exception as e:
            logger.error(
                f"Unexpected error in pod watcher: {e}. Retrying in 30s.", exc_info=True
            )
            time.sleep(30)
        finally:
            # Clean up any threads that might have exited unexpectedly without being removed
            # This is a safety net; primary cleanup should happen on DELETED or non-Running MODIFIED events
            with archival_lock:
                stale_pods = []
                for pod_name, info in active_archivals.items():
                    if not info["thread"].is_alive():
                        logger.warning(
                            f"Archival thread for {pod_name} found dead. Cleaning up."
                        )
                        info[
                            "stop_event"
                        ].set()  # Ensure event is set if thread died before setting it
                        stale_pods.append(pod_name)
                for pod_name in stale_pods:
                    active_archivals.pop(pod_name, None)


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
