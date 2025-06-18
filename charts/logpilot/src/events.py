#! /usr/bin/env python3
import argparse
import asyncio
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import kubernetes  # type: ignore
import rich.box  # type: ignore
from kge import __version__

# Prompt-toolkit imports
from prompt_toolkit import Application  # type: ignore
from prompt_toolkit.formatted_text import FormattedText, to_formatted_text  # type: ignore
from prompt_toolkit.key_binding import KeyBindings  # type: ignore
from prompt_toolkit.layout import HSplit, Layout, Window  # type: ignore
from prompt_toolkit.layout.controls import FormattedTextControl  # type: ignore
from prompt_toolkit.styles import Style  # type: ignore
from rich.console import Console  # type: ignore
from rich.table import Table  # type: ignore
from rich.text import Text  # type: ignore

# Initialize Rich Console
console = Console()


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
    api_version: Optional[str]  # API version of the involved_object
    type: Optional[str]
    count: Optional[int]
    involved_object_uid: Optional[str]  # UID of the involved_object

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


class KubernetesEventManager:
    """Manages Kubernetes events fetching and processing."""

    def __init__(self) -> None:
        self._object_fetch_cache: Dict[Tuple, Optional[Any]] = {}  # Cache for fetched K8s objects
        self._owner_resolution_cache: Dict[Tuple, Dict[str, str]] = {}  # Cache for resolved owners
        self._init_kubernetes_client()

    def _init_kubernetes_client(self) -> None:
        """Initialize the Kubernetes client with proper configuration."""
        try:
            # Try to load in-cluster config first
            kubernetes.config.load_incluster_config()
            console.print("[green]Using in-cluster configuration[/green]")
        except kubernetes.config.ConfigException:
            try:
                # Fallback to kubeconfig
                kubernetes.config.load_kube_config()
                console.print("[green]Using kubeconfig configuration[/green]")
            except kubernetes.config.ConfigException:
                console.print("[red]Could not configure Kubernetes client.[/red]")
                console.print(
                    "[yellow]Please ensure you have a valid kubeconfig file or are running in-cluster.[/yellow]"
                )
                console.print(
                    "[yellow]You can set KUBECONFIG environment variable to specify a custom kubeconfig path.[/yellow]"
                )
                raise Exception(
                    "Could not configure Kubernetes client. "
                    "Ensure you have a valid kubeconfig or are running in-cluster."
                )

        self.v1 = kubernetes.client.CoreV1Api()
        self.apps_v1 = kubernetes.client.AppsV1Api()
        self.batch_v1 = kubernetes.client.BatchV1Api()

    def _fetch_k8s_object(self, namespace: str, kind: str, name: str, api_version: Optional[str]) -> Optional[Any]:
        cache_key = (namespace, kind, name, api_version)
        if cache_key in self._object_fetch_cache:
            return self._object_fetch_cache[cache_key]
        obj = None
        try:
            if kind == "Pod" and (api_version == "v1" or not api_version):
                obj = self.v1.read_namespaced_pod(name=name, namespace=namespace)
            elif kind == "ReplicaSet" and api_version == "apps/v1":
                obj = self.apps_v1.read_namespaced_replica_set(name=name, namespace=namespace)
            elif kind == "Deployment" and api_version == "apps/v1":
                obj = self.apps_v1.read_namespaced_deployment(name=name, namespace=namespace)
            elif kind == "StatefulSet" and api_version == "apps/v1":
                obj = self.apps_v1.read_namespaced_stateful_set(name=name, namespace=namespace)
            elif kind == "DaemonSet" and api_version == "apps/v1":
                obj = self.apps_v1.read_namespaced_daemon_set(name=name, namespace=namespace)
            elif kind == "Job" and api_version == "batch/v1":
                obj = self.batch_v1.read_namespaced_job(name=name, namespace=namespace)
            elif kind == "CronJob" and (api_version == "batch/v1" or api_version == "batch/v1beta1"):
                obj = self.batch_v1.read_namespaced_cron_job(name=name, namespace=namespace)
            elif kind == "Node" and (api_version == "v1" or not api_version):
                obj = self.v1.read_node(name=name)
        except kubernetes.client.exceptions.ApiException as e:
            if e.status != 404:  # Log other errors, 404 is common if object deleted
                # console.print(f"[yellow]API Error fetching {kind}/{name} in {namespace}: {e.status} - {e.reason}[/yellow]")
                pass
        except Exception:
            # console.print(f"[red]Unexpected error fetching {kind}/{name}: {e}[/red]")
            pass
        self._object_fetch_cache[cache_key] = obj
        return obj

    def _get_true_owner_recursive(
        self, namespace: str, owner_ref: Any, level: int = 0, max_level: int = 5
    ) -> Dict[str, str]:
        cache_key = (namespace, owner_ref.kind, owner_ref.name, str(owner_ref.uid))
        if cache_key in self._owner_resolution_cache:
            return self._owner_resolution_cache[cache_key]

        if level >= max_level:
            resolved_owner = {
                "kind": owner_ref.kind,
                "name": owner_ref.name,
                "namespace": namespace,
                "uid": str(owner_ref.uid),
            }
            self._owner_resolution_cache[cache_key] = resolved_owner
            return resolved_owner

        obj = self._fetch_k8s_object(namespace, owner_ref.kind, owner_ref.name, owner_ref.api_version)

        if obj and hasattr(obj, "metadata") and obj.metadata.owner_references:
            result = self._get_true_owner_recursive(
                obj.metadata.namespace,
                obj.metadata.owner_references[0],
                level + 1,
                max_level,
            )
            self._owner_resolution_cache[cache_key] = result
            return result
        else:
            resolved_owner = {
                "kind": owner_ref.kind,
                "name": owner_ref.name,
                "namespace": namespace,
                "uid": str(owner_ref.uid),
            }
            self._owner_resolution_cache[cache_key] = resolved_owner
            return resolved_owner

    def group_events_by_owner(self, events: List[KubernetesEvent]) -> Dict[str, Dict[str, Any]]:
        grouped_by_owner_uid: Dict[str, Dict[str, Any]] = {}
        involved_to_final_owner_cache: Dict[Tuple, Dict[str, str]] = {}

        for event in events:
            if not event.involved_object_name or not event.involved_object_kind or not event.namespace:
                continue

            involved_key_uid_part = (
                event.involved_object_uid if event.involved_object_uid else f"no-uid-{event.involved_object_name}"
            )
            involved_key = (
                event.namespace,
                event.involved_object_kind,
                event.involved_object_name,
                involved_key_uid_part,
            )
            effective_owner_info: Optional[Dict[str, str]] = None

            if involved_key in involved_to_final_owner_cache:
                effective_owner_info = involved_to_final_owner_cache[involved_key]
            else:
                involved_obj_full = self._fetch_k8s_object(
                    event.namespace,
                    event.involved_object_kind,
                    event.involved_object_name,
                    event.api_version,
                )
                if (
                    involved_obj_full
                    and hasattr(involved_obj_full, "metadata")
                    and involved_obj_full.metadata.owner_references
                ):
                    direct_owner_ref = involved_obj_full.metadata.owner_references[0]
                    effective_owner_info = self._get_true_owner_recursive(
                        involved_obj_full.metadata.namespace, direct_owner_ref
                    )
                elif involved_obj_full and hasattr(involved_obj_full, "metadata"):
                    effective_owner_info = {
                        "kind": getattr(involved_obj_full, "kind", event.involved_object_kind),
                        "name": involved_obj_full.metadata.name,
                        "namespace": involved_obj_full.metadata.namespace,
                        "uid": str(involved_obj_full.metadata.uid),
                    }
                else:
                    effective_owner_info = {
                        "kind": event.involved_object_kind,
                        "name": event.involved_object_name,
                        "namespace": event.namespace,
                        "uid": event.involved_object_uid
                        or f"fallback-uid-{event.namespace}-{event.involved_object_kind}-{event.involved_object_name}",
                    }
                involved_to_final_owner_cache[involved_key] = effective_owner_info

            if not effective_owner_info or not effective_owner_info.get("uid"):
                continue

            owner_uid_str = effective_owner_info["uid"]
            if owner_uid_str not in grouped_by_owner_uid:
                initial_ts = event.last_timestamp or event.first_timestamp
                initial_ts = (
                    initial_ts.replace(tzinfo=timezone.utc)
                    if initial_ts and initial_ts.tzinfo is None
                    else (initial_ts or datetime.min.replace(tzinfo=timezone.utc))
                )
                grouped_by_owner_uid[owner_uid_str] = {
                    "owner_info": effective_owner_info,
                    "events": [],
                    "latest_event_timestamp": initial_ts,
                    "latest_event_type": event.type or "N/A",
                    "latest_event_reason": event.reason or "N/A",
                }

            grouped_by_owner_uid[owner_uid_str]["events"].append(event)
            current_event_ts = event.last_timestamp or event.first_timestamp
            if current_event_ts:
                current_event_ts = (
                    current_event_ts.replace(tzinfo=timezone.utc)
                    if current_event_ts.tzinfo is None
                    else current_event_ts
                )
                if current_event_ts > grouped_by_owner_uid[owner_uid_str]["latest_event_timestamp"]:
                    grouped_by_owner_uid[owner_uid_str]["latest_event_timestamp"] = current_event_ts
                    grouped_by_owner_uid[owner_uid_str]["latest_event_type"] = event.type or "N/A"
                    grouped_by_owner_uid[owner_uid_str]["latest_event_reason"] = event.reason or "N/A"

        for owner_data in grouped_by_owner_uid.values():
            owner_data["events"].sort(
                key=lambda e: (
                    (e.last_timestamp or e.first_timestamp or datetime.min).replace(tzinfo=timezone.utc)
                    if (e.last_timestamp or e.first_timestamp or datetime.min).tzinfo is None
                    else (e.last_timestamp or e.first_timestamp or datetime.min)
                ),
                reverse=True,
            )
        return grouped_by_owner_uid

    def fetch_events(self, namespace: Optional[str] = None) -> List[KubernetesEvent]:
        self._object_fetch_cache.clear()
        self._owner_resolution_cache.clear()
        try:
            if namespace:
                console.print(f"[cyan]Fetching events for namespace: {namespace}[/cyan]")
                events_list_response = self.v1.list_namespaced_event(namespace=namespace, watch=False, limit=500)
            else:
                console.print("[cyan]Fetching events for all namespaces[/cyan]")
                events_list_response = self.v1.list_event_for_all_namespaces(watch=False, limit=1000)
            return [KubernetesEvent.from_v1_event(event) for event in events_list_response.items]
        except kubernetes.client.exceptions.ApiException as e:
            console.print(f"[red]Error fetching events (Kubernetes API): {e.status} - {e.reason}[/red]")
            if hasattr(e, "body"):
                console.print(f"[red]API Error Body: {e.body}[/red]")
            return []
        except Exception as e:
            console.print(f"[red]Unexpected error fetching events: {e}[/red]")
            import traceback

            console.print(traceback.format_exc())
            return []

    def filter_events(
        self,
        events: List[KubernetesEvent],
        kind_filter: Optional[str] = None,
        type_filter: Optional[str] = None,
    ) -> List[KubernetesEvent]:
        filtered_events = events
        if kind_filter:
            filtered_events = [
                e
                for e in filtered_events
                if e.involved_object_kind and kind_filter.lower() in e.involved_object_kind.lower()
            ]
        if type_filter:
            filtered_events = [e for e in filtered_events if e.type and type_filter.lower() in e.type.lower()]
        return filtered_events

    def display_events_table(
        self,
        events: List[KubernetesEvent],
        show_timestamps: bool = False,
        show_all_namespaces: bool = False,
    ) -> None:
        if not events:
            console.print("[yellow]No events found to display for the selected owner after filtering.[/yellow]")
            return
        table = Table(
            show_header=True,
            header_style="bold white",
            box=rich.box.ROUNDED,
            show_lines=True,
            padding=(0, 1),
            border_style="dim white",
            style="white",
        )
        table.add_column("Time", no_wrap=True)
        table.add_column("Type", no_wrap=True)
        table.add_column("Reason", no_wrap=True)
        table.add_column("Type/Involved Object", no_wrap=True)
        table.add_column("Message")

        now = datetime.now(timezone.utc)

        # Ensure events are sorted for display; grouping already sorts them, but this is a safeguard
        def ensure_aware(dt: Optional[datetime]) -> datetime:
            if dt is None:
                return datetime.min.replace(tzinfo=timezone.utc)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt

        sorted_events = sorted(
            events,
            key=lambda event: ensure_aware(event.last_timestamp or event.first_timestamp),
            reverse=True,
        )

        for event in sorted_events:
            ts_to_format = event.last_timestamp or event.first_timestamp
            if ts_to_format:
                ts_to_format = (
                    ts_to_format.replace(tzinfo=timezone.utc) if ts_to_format.tzinfo is None else ts_to_format
                )
            timestamp_str: str
            if show_timestamps or not ts_to_format:
                timestamp_str = str(ts_to_format) if ts_to_format else "unknown time"
            else:
                delta = now - ts_to_format
                if delta.total_seconds() < 0:
                    timestamp_str = "in future?"
                elif delta.days > 0:
                    timestamp_str = f"{delta.days}d ago"
                elif delta.seconds >= 3600:
                    timestamp_str = f"{delta.seconds // 3600}h ago"
                elif delta.seconds >= 60:
                    timestamp_str = f"{delta.seconds // 60}m ago"
                else:
                    timestamp_str = f"{delta.seconds}s ago"
            resource_str = (
                f"{event.involved_object_kind or 'UnknownKind'}/{event.involved_object_name or 'UnknownName'}"
            )
            table.add_row(
                Text(timestamp_str, style="cyan"),
                Text(
                    event.type or "N/A",
                    style="red" if event.type and event.type != "Normal" else "white",
                ),
                Text(event.reason or "N/A", style="cyan"),
                Text(resource_str, style="white"),
                Text(
                    event.message or "",
                    style="red" if event.type and event.type != "Normal" else "white",
                ),
            )
        console.print(table)


class KubeEventsInteractiveSelector:
    def __init__(
        self,
        grouped_data: Dict[str, Dict[str, Any]],
        show_timestamps: bool = False,
        show_all_namespaces: bool = False,
    ):
        if show_timestamps:
            sort_reverse = False
        else:
            sort_reverse = True
        self.grouped_data = grouped_data
        self.show_timestamps = show_timestamps
        self.show_all_namespaces = show_all_namespaces
        self.sorted_owner_uids = sorted(
            self.grouped_data.keys(),
            key=lambda uid: (
                self.grouped_data[uid]["latest_event_timestamp"] or datetime.min.replace(tzinfo=timezone.utc)
            ),
            reverse=sort_reverse,
        )
        self.selected_index = 0
        self.result_events: Optional[List[KubernetesEvent]] = None

        self.key_bindings = KeyBindings()
        self._setup_key_bindings()

        # Define styles as actual prompt_toolkit style strings
        self.style_definitions = {
            "selected-row": "bg:#ansiblue #ansiyellow",  # Original: blue bg, yellow text
            "header": "bold #ansimagenta",
            "normal-row": "",  # Default style (no special formatting)
            "info": "bold #ansicyan",
            "type-warning-override-fg": "fg:#ffff00 bold",  # yellow foreground for non-Normal types + bold
        }
        self.style = Style.from_dict(self.style_definitions)

    def _format_relative_time(self, timestamp: Optional[datetime]) -> str:
        if timestamp is None:
            return "unknown time"
        ts_aware = timestamp.replace(tzinfo=timezone.utc) if timestamp.tzinfo is None else timestamp
        if self.show_timestamps:
            return str(ts_aware)
        now = datetime.now(timezone.utc)
        delta = now - ts_aware
        if delta.total_seconds() < 0:
            return "in future?"
        if delta.days > 0:
            return f"{delta.days}d ago"
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, _ = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h ago"
        if minutes > 0:
            return f"{minutes}m ago"
        return f"{delta.seconds}s ago"

    def _get_list_content(self) -> FormattedText:
        lines = []
        lines.append(
            (
                self.style_definitions["header"],
                "Select an owner using ↑↓, press Enter to view details, 'q' to quit.\n",
            )
        )

        if not self.sorted_owner_uids:
            lines.append((self.style_definitions["info"], "No event groups to display.\n"))
            return to_formatted_text(lines)

        # Calculate maximum widths for each column
        max_time_width = 27 if self.show_timestamps else 15  # Wider for timestamps
        max_type_width = 10  # Fixed width for type
        max_reason_width = 15  # Initial width for reason
        max_resource_width = 60  # Initial width for resource
        max_namespace_width = 20  # Initial width for namespace

        # Calculate actual maximum widths from data
        for owner_uid in self.sorted_owner_uids:
            data = self.grouped_data[owner_uid]
            owner_info = data["owner_info"]
            resource_name_str = f"{owner_info.get('kind', 'N/A')}/{owner_info.get('name', 'N/A')}"
            owner_namespace_str = owner_info.get("namespace", "cluster") or "cluster"
            reason_str = data["latest_event_reason"]

            max_resource_width = max(max_resource_width, len(resource_name_str))
            max_namespace_width = max(max_namespace_width, len(owner_namespace_str))
            max_reason_width = max(max_reason_width, len(reason_str))

        # Calculate total width
        if self.show_all_namespaces:
            total_width = (
                max_namespace_width + max_time_width + max_type_width + max_reason_width + max_resource_width + 10
            )
        else:
            total_width = max_time_width + max_type_width + max_reason_width + max_resource_width + 6

        # If total width exceeds 140, truncate reason column to 30 characters
        if total_width > 140:
            max_reason_width = 30
            if self.show_all_namespaces:
                total_width = (
                    max_namespace_width + max_time_width + max_type_width + max_reason_width + max_resource_width + 10
                )
            else:
                total_width = max_time_width + max_type_width + max_reason_width + max_resource_width + 6

        header_style_str = self.style_definitions["info"]
        # Create format string with dynamic widths
        if self.show_all_namespaces:
            format_str = f"{{:<{max_namespace_width}}}  {{:<{max_time_width}}}  {{:<{max_type_width}}}  {{:<{max_reason_width}}}  {{:<{max_resource_width}}}\n"
            header = format_str.format("Namespace", "Time", "Type", "Reason", "Owner Resource")
        else:
            format_str = f"{{:<{max_time_width}}}  {{:<{max_type_width}}}  {{:<{max_reason_width}}}  {{:<{max_resource_width}}}\n"
            header = format_str.format("Time", "Type", "Reason", "Owner Resource")

        lines.append((header_style_str, header))
        lines.append((header_style_str, "-" * total_width + "\n"))

        for i, owner_uid in enumerate(self.sorted_owner_uids):
            data = self.grouped_data[owner_uid]
            owner_info = data["owner_info"]
            resource_name_str = f"{owner_info.get('kind', 'N/A')}/{owner_info.get('name', 'N/A')}"
            owner_namespace_str = owner_info.get("namespace", "cluster") or "cluster"

            time_str = self._format_relative_time(data["latest_event_timestamp"])
            type_str = data["latest_event_type"]
            reason_str = data["latest_event_reason"]

            # Truncate reason if needed
            if len(reason_str) > max_reason_width:
                reason_str = reason_str[: max_reason_width - 3] + "..."

            is_selected = i == self.selected_index

            other_parts_style_str = (
                self.style_definitions["selected-row"] if is_selected else self.style_definitions["normal-row"]
            )
            type_cell_style_str = other_parts_style_str
            if type_str != "Normal":
                type_cell_style_str = (
                    type_cell_style_str + " " + self.style_definitions["type-warning-override-fg"]
                ).strip()

            # Use the dynamic format string
            if self.show_all_namespaces:
                current_line_parts = [
                    (
                        other_parts_style_str.strip(),
                        f"{owner_namespace_str:<{max_namespace_width}}  ",
                    ),
                    (other_parts_style_str.strip(), f"{time_str:<{max_time_width}}  "),
                    (type_cell_style_str.strip(), f"{type_str:<{max_type_width}}  "),
                    (
                        other_parts_style_str.strip(),
                        f"{reason_str:<{max_reason_width}}  {resource_name_str:<{max_resource_width}}\n",
                    ),
                ]
            else:
                current_line_parts = [
                    (other_parts_style_str.strip(), f"{time_str:<{max_time_width}}  "),
                    (type_cell_style_str.strip(), f"{type_str:<{max_type_width}}  "),
                    (
                        other_parts_style_str.strip(),
                        f"{reason_str:<{max_reason_width}}  {resource_name_str:<{max_resource_width}}\n",
                    ),
                ]
            lines.extend(current_line_parts)

        return to_formatted_text(lines)

    def _setup_key_bindings(self) -> None:
        @self.key_bindings.add("up")  # type: ignore[misc]
        def _(event: Any) -> None:
            self.selected_index = max(0, self.selected_index - 1)

        @self.key_bindings.add("down")  # type: ignore[misc]
        def _(event: Any) -> None:
            self.selected_index = min(len(self.sorted_owner_uids) - 1, self.selected_index + 1)

        @self.key_bindings.add("enter")  # type: ignore[misc]
        def _(event: Any) -> None:
            if self.sorted_owner_uids:
                selected_uid = self.sorted_owner_uids[self.selected_index]
                self.result_events = self.grouped_data[selected_uid]["events"]
                event.app.exit(self.result_events)
            else:
                event.app.exit(None)

        @self.key_bindings.add("c-c", eager=True)  # type: ignore[misc]
        @self.key_bindings.add("q", eager=True)  # type: ignore[misc]
        def _(event: Any) -> None:
            self.result_events = None
            event.app.exit(None)

    def run(self) -> Optional[List[KubernetesEvent]]:
        root_container = HSplit([Window(content=FormattedTextControl(self._get_list_content, show_cursor=False))])

        application = Application(
            layout=Layout(root_container),
            key_bindings=self.key_bindings,
            full_screen=True,
            style=self.style,
        )

        self.result_events = application.run()

        return self.result_events


def main() -> None:
    parser = argparse.ArgumentParser(description="View Kubernetes events with an interactive list, grouped by owner.")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-A", "--all", action="store_true", help="Fetch events from all namespaces")
    parser.add_argument(
        "-n",
        "--namespace",
        help="Namespace to fetch events from (default: current context namespace)",
    )
    parser.add_argument("-k", "--kind", help="Filter selected owner's events by involved object kind")
    parser.add_argument("-t", "--type", help="Filter selected owner's events by type")
    parser.add_argument("--show-timestamps", action="store_true", help="Show absolute timestamps")
    parser.add_argument(
        "--completion",
        choices=["zsh"],
        help="Generate shell completion script",
    )
    # Hidden completion flags for zsh completion script
    parser.add_argument("--complete-ns", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--complete-kind", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Handle completion script generation
    if args.completion:
        from kge.completion import install_completion

        install_completion()
        sys.exit(0)

    # Handle completion-specific flags
    if args.complete_ns:
        try:
            kubernetes.config.load_kube_config()
            v1 = kubernetes.client.CoreV1Api()
            namespaces = v1.list_namespace()
            for ns in namespaces.items:
                print(ns.metadata.name)
            sys.exit(0)
        except Exception as e:
            print(f"Error fetching namespaces: {e}", file=sys.stderr)
            sys.exit(1)

    if args.complete_kind:
        # Common Kubernetes resource kinds
        kinds = [
            "Pod",
            "Deployment",
            "StatefulSet",
            "DaemonSet",
            "ReplicaSet",
            "Job",
            "CronJob",
            "Service",
            "ConfigMap",
            "Secret",
            "PersistentVolumeClaim",
            "PersistentVolume",
            "Node",
        ]
        for kind in kinds:
            print(kind)
        sys.exit(0)

    event_manager_instance: Optional[KubernetesEventManager] = None
    selected_owner_events_from_selector: Optional[List[KubernetesEvent]] = None

    try:
        event_manager_instance = KubernetesEventManager()

        if args.all:
            namespace_arg = None
        elif args.namespace is not None:
            namespace_arg = args.namespace
        else:
            try:
                _, current_context_dict = kubernetes.config.list_kube_config_contexts()
                namespace_arg = current_context_dict.get("context", {}).get("namespace")
                if not namespace_arg:
                    console.print(
                        "[yellow]Current context does not have a namespace specified. Consider using -n <namespace> or --all.[/yellow]"
                    )
                    # Defaulting to None will make fetch_events get all namespaces.
                    namespace_arg = None
            except Exception as e:
                console.print(
                    f"[yellow]Could not determine current namespace: {e}. Defaulting to all namespaces.[/yellow]"
                )
                namespace_arg = None

        console.print("[cyan]Loading events from Kubernetes...[/cyan]")
        all_events: Optional[List[KubernetesEvent]] = asyncio.run(
            asyncio.to_thread(event_manager_instance.fetch_events, namespace_arg)
        )
        if not all_events:
            ns_display = namespace_arg or "all"
            console.print(f"[yellow]No recent events found in the {ns_display} namespace(s).[/yellow]")
            sys.exit(0)

        console.print("[cyan]Grouping events by owner...[/cyan]")
        grouped_data = asyncio.run(asyncio.to_thread(event_manager_instance.group_events_by_owner, all_events))

        if not grouped_data:
            console.print("[yellow]No event groups to display after processing.[/yellow]")
            sys.exit(0)

        selector = KubeEventsInteractiveSelector(
            grouped_data=grouped_data,
            show_timestamps=args.show_timestamps,
            show_all_namespaces=args.all,
        )
        selected_owner_events_from_selector = selector.run()

        if selected_owner_events_from_selector:
            console.print(
                f"\n[white]Detailed Events for[/white]"
                f"[cyan] {selected_owner_events_from_selector[0].involved_object_kind or 'UnknownKind'} "
                f"{selected_owner_events_from_selector[0].involved_object_name}[/cyan]"
                f"[white] in namespace:[/white] [cyan]{selected_owner_events_from_selector[0].namespace or 'cluster'}[/cyan]"
            )
            filtered_selected_events = event_manager_instance.filter_events(
                selected_owner_events_from_selector,
                kind_filter=args.kind,
                type_filter=args.type,
            )
            event_manager_instance.display_events_table(filtered_selected_events, args.show_timestamps, args.all)
        else:
            console.print("\n[yellow]No owner selected or selection cancelled.[/yellow]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Keyboard interrupt detected. Exiting gracefully...[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred in main execution: {e}[/bold red]")
        import traceback

        console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
