"""Network monitoring tools for eBPF-based network event analysis.

This module provides tools to read, analyze, and detect anomalies in network
events collected by the eBPF network monitoring agent. The agent writes events
to /var/log/network-events.jsonl in JSON Lines format.
"""

import json
import logging

from collections import Counter
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Optional

from .ssh_executor import execute_command
from .validation import validate_positive_int


logger = logging.getLogger(__name__)

# Default log file path where eBPF agent writes events
DEFAULT_LOG_PATH = "/var/log/network-events.jsonl"

# Well-known backdoor/suspicious ports
SUSPICIOUS_PORTS = {
    31337,
    12345,
    54321,
    1337,
    6667,
    6668,
    6669,  # Common backdoor ports
    4444,
    5555,
    7777,
    8888,
    9999,  # Generic backdoor ports
    1234,
    27374,
    27665,
    31338,
    31339,  # NetBus, Trinoo, etc.
}


def parse_iso_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse ISO 8601 timestamp string to datetime object.

    Args:
        timestamp_str: ISO 8601 timestamp string

    Returns:
        datetime object with UTC timezone or None if parsing fails
    """
    try:
        # Handle both with and without timezone
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(timestamp_str)

        # If datetime is naive (no timezone), assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt
    except (ValueError, AttributeError):
        return None


async def read_event_log(
    log_path: str,
    minutes: int,
    host: Optional[str] = None,
    username: Optional[str] = None,
) -> tuple[list[dict], Optional[str]]:
    """
    Read and parse network event log file.

    Args:
        log_path: Path to the log file
        minutes: Time window in minutes
        host: Optional remote host
        username: Optional SSH username

    Returns:
        Tuple of (events_list, error_message)
    """
    try:
        # Calculate cutoff time
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes)

        # Read the log file using tail (optimize for large files)
        # Estimate ~2 events per second worst case, so 120 * minutes should be enough
        estimated_lines = max(120 * minutes, 1000)

        returncode, stdout, stderr = await execute_command(
            ["tail", "-n", str(estimated_lines), log_path],
            host=host,
            username=username,
        )

        if returncode != 0:
            if "No such file or directory" in stderr:
                return (
                    [],
                    f"Network event log not found at {log_path}. The eBPF agent may not be running or logging to a different location.",
                )
            if "Permission denied" in stderr:
                return [], f"Permission denied reading {log_path}. Root privileges may be required."
            return [], f"Error reading log file: {stderr}"

        if not stdout or stdout.strip() == "":
            return [], None  # Empty log is valid

        # Parse JSONL format
        events = []
        for line_num, line in enumerate(stdout.strip().split("\n"), 1):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)

                # Parse and filter by timestamp
                timestamp_str = event.get("timestamp", "")
                event_time = parse_iso_timestamp(timestamp_str)

                if event_time and event_time >= cutoff_time:
                    events.append(event)
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping invalid JSON on line {line_num}: {e}")
                continue

        return events, None

    except Exception as e:
        return [], f"Error reading event log: {str(e)}"


async def get_network_events_history(
    minutes: int = 30,
    filter_by_process: Optional[str] = None,
    filter_by_port: Optional[int] = None,
    host: Optional[str] = None,
    username: Optional[str] = None,
) -> str:
    """
    Get network event history from eBPF collector logs.

    Retrieves network events collected by the eBPF monitoring agent,
    with optional filtering by process name or port number.

    Args:
        minutes: Time window in minutes (default: 30)
        filter_by_process: Filter events by process name (optional)
        filter_by_port: Filter events by port number (optional)
        host: Optional remote host to connect to
        username: Optional SSH username (required if host is provided)

    Returns:
        Formatted string with network event history
    """
    try:
        # Validate minutes parameter
        minutes, error = validate_positive_int(minutes, "minutes", min_value=1, max_value=1440)
        if error:
            return error

        # Validate port if provided
        if filter_by_port is not None:
            filter_by_port, error = validate_positive_int(filter_by_port, "port", min_value=1, max_value=65535)
            if error:
                return error

        # Read events
        events, error = await read_event_log(DEFAULT_LOG_PATH, minutes, host, username)
        if error:
            return error

        if not events:
            return f"No network events found in the last {minutes} minute(s)."

        # Apply filters
        filtered_events = events

        if filter_by_process:
            filtered_events = [
                e
                for e in filtered_events
                if filter_by_process.lower() in e.get("process_details", {}).get("command", "").lower()
            ]

        if filter_by_port is not None:
            filtered_events = [
                e
                for e in filtered_events
                if (
                    e.get("communication_target", {}).get("remote_port") == filter_by_port
                    or e.get("source", {}).get("local_port") == filter_by_port
                )
            ]

        if not filtered_events:
            filters = []
            if filter_by_process:
                filters.append(f"process='{filter_by_process}'")
            if filter_by_port:
                filters.append(f"port={filter_by_port}")
            filter_desc = " AND ".join(filters)
            return f"No network events found matching filters: {filter_desc}"

        # Format output
        result = []
        result.append(f"=== Network Events (last {minutes} minute(s), {len(filtered_events)} events) ===\n")

        # Add filter description if filters were applied
        if filter_by_process or filter_by_port:
            filters = []
            if filter_by_process:
                filters.append(f"process='{filter_by_process}'")
            if filter_by_port:
                filters.append(f"port={filter_by_port}")
            result.append(f"Filters: {' AND '.join(filters)}\n")

        # Format each event
        for event in filtered_events[-100:]:  # Limit to last 100 events
            timestamp = event.get("timestamp", "unknown")
            process = event.get("process_details", {})
            pid = process.get("pid", "unknown")
            command = process.get("command", "unknown")

            ipc_mechanism = event.get("network_ipc_mechanism", "unknown")
            protocol = event.get("transport_protocol", "unknown")

            target = event.get("communication_target", {})
            remote_addr = target.get("remote_address", "unknown")
            remote_port = target.get("remote_port", "unknown")
            app_protocol = target.get("identified_application_protocol", "unknown")

            source = event.get("source", {})
            local_addr = source.get("local_address", "unknown")
            local_port = source.get("local_port", "unknown")

            result.append(f"[{timestamp}]")
            result.append(f"  Process: {command} (PID: {pid})")
            result.append(f"  Type: {ipc_mechanism} ({protocol})")
            result.append(f"  Source: {local_addr}:{local_port}")
            result.append(f"  Target: {remote_addr}:{remote_port} ({app_protocol})")
            result.append("")

        if len(filtered_events) > 100:
            result.append(f"\n(Showing last 100 of {len(filtered_events)} events)")

        return "\n".join(result)

    except Exception as e:
        return f"Error retrieving network events: {str(e)}"


async def detect_network_anomalies(
    minutes: int = 30,
    host: Optional[str] = None,
    username: Optional[str] = None,
) -> str:
    """
    Analyze network events and detect suspicious patterns.

    Detects various anomalies including:
    - High connection rate (potential DDoS or scanning)
    - Port scanning behavior
    - Connections to unusual/suspicious ports
    - New processes with network activity
    - Failed connection patterns

    Args:
        minutes: Time window in minutes (default: 30)
        host: Optional remote host to connect to
        username: Optional SSH username (required if host is provided)

    Returns:
        Structured report of detected anomalies with severity levels
    """
    try:
        # Validate minutes parameter
        minutes, error = validate_positive_int(minutes, "minutes", min_value=1, max_value=1440)
        if error:
            return error

        # Read events
        events, error = await read_event_log(DEFAULT_LOG_PATH, minutes, host, username)
        if error:
            return error

        if not events:
            return f"No network events found in the last {minutes} minute(s) to analyze."

        # Initialize anomaly tracking
        anomalies = []

        # Track metrics for analysis
        process_connection_count = Counter()
        process_unique_ports = defaultdict(set)
        process_unique_ips = defaultdict(set)
        port_access_count = Counter()
        suspicious_port_access = defaultdict(list)
        processes_seen = set()

        # Analyze each event
        for event in events:
            process = event.get("process_details", {})
            command = process.get("command", "unknown")
            pid = process.get("pid", "unknown")
            process_key = f"{command}:{pid}"

            target = event.get("communication_target", {})
            remote_port = target.get("remote_port", 0)
            remote_addr = target.get("remote_address", "unknown")

            # Track metrics
            process_connection_count[process_key] += 1
            process_unique_ports[process_key].add(remote_port)
            process_unique_ips[process_key].add(remote_addr)
            port_access_count[remote_port] += 1
            processes_seen.add(command)

            # Check for suspicious ports
            if remote_port in SUSPICIOUS_PORTS:
                suspicious_port_access[process_key].append(
                    {"port": remote_port, "address": remote_addr, "timestamp": event.get("timestamp", "unknown")}
                )

        # Anomaly Detection Rules

        # 1. High connection rate
        high_rate_threshold = 50
        for process_key, count in process_connection_count.items():
            if count > high_rate_threshold:
                anomalies.append(
                    {
                        "severity": "HIGH",
                        "type": "High Connection Rate",
                        "process": process_key,
                        "details": f"{count} connections in {minutes} minute(s)",
                        "reason": "Unusually high number of connections may indicate scanning, DDoS, or data exfiltration",
                    }
                )

        # 2. Port scanning detection
        port_scan_threshold = 20
        for process_key, ports in process_unique_ports.items():
            if len(ports) > port_scan_threshold:
                anomalies.append(
                    {
                        "severity": "CRITICAL",
                        "type": "Port Scanning",
                        "process": process_key,
                        "details": f"Accessed {len(ports)} different ports",
                        "reason": "Connecting to many different ports is typical scanning behavior",
                    }
                )

        # 3. Suspicious port access
        for process_key, accesses in suspicious_port_access.items():
            for access in accesses:
                anomalies.append(
                    {
                        "severity": "CRITICAL",
                        "type": "Suspicious Port Access",
                        "process": process_key,
                        "details": f"Port {access['port']} to {access['address']}",
                        "reason": f"Port {access['port']} is commonly associated with backdoors or malware",
                    }
                )

        # 4. High-numbered ephemeral port connections (potential backdoor listeners)
        high_port_threshold = 60000
        high_port_processes = defaultdict(int)
        for event in events:
            target = event.get("communication_target", {})
            remote_port = target.get("remote_port", 0)

            if remote_port > high_port_threshold:
                process = event.get("process_details", {})
                process_key = f"{process.get('command', 'unknown')}:{process.get('pid', 'unknown')}"
                high_port_processes[process_key] += 1

        for process_key, count in high_port_processes.items():
            if count > 5:
                anomalies.append(
                    {
                        "severity": "MEDIUM",
                        "type": "High Port Usage",
                        "process": process_key,
                        "details": f"{count} connections to ports > {high_port_threshold}",
                        "reason": "Connections to very high-numbered ports may indicate custom backdoor communication",
                    }
                )

        # 5. Multiple IP addresses contacted by single process
        multi_ip_threshold = 30
        for process_key, ips in process_unique_ips.items():
            if len(ips) > multi_ip_threshold:
                anomalies.append(
                    {
                        "severity": "MEDIUM",
                        "type": "Multiple Remote Hosts",
                        "process": process_key,
                        "details": f"Contacted {len(ips)} different IP addresses",
                        "reason": "Connecting to many different IPs may indicate scanning or botnet activity",
                    }
                )

        # Format output
        result = []
        result.append("=== Network Anomaly Detection Report ===")
        result.append(f"Analysis Window: Last {minutes} minute(s)")
        result.append(f"Events Analyzed: {len(events)}")
        result.append(f"Anomalies Detected: {len(anomalies)}\n")

        if not anomalies:
            result.append("✓ No anomalies detected. Network activity appears normal.\n")

            # Show summary statistics
            result.append("Summary Statistics:")
            result.append(f"  Total Connections: {len(events)}")
            result.append(f"  Unique Processes: {len(process_connection_count)}")
            result.append(f"  Unique Ports: {len(port_access_count)}")

            return "\n".join(result)

        # Sort anomalies by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        anomalies.sort(key=lambda x: severity_order.get(x["severity"], 99))

        # Group by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity_anomalies = [a for a in anomalies if a["severity"] == severity]
            if not severity_anomalies:
                continue

            result.append(f"\n{'=' * 60}")
            result.append(f"[{severity}] - {len(severity_anomalies)} anomaly(ies)")
            result.append(f"{'=' * 60}\n")

            for anomaly in severity_anomalies:
                result.append(f"Type: {anomaly['type']}")
                result.append(f"Process: {anomaly['process']}")
                result.append(f"Details: {anomaly['details']}")
                result.append(f"Reason: {anomaly['reason']}")
                result.append("")

        result.append(f"\n{'=' * 60}")
        result.append("RECOMMENDATIONS:")
        result.append("- Investigate CRITICAL and HIGH severity anomalies immediately")
        result.append("- Review process behavior and validate legitimacy")
        result.append("- Check for signs of compromise or unauthorized access")
        result.append("- Consider firewall rules for suspicious connections")

        return "\n".join(result)

    except Exception as e:
        return f"Error detecting network anomalies: {str(e)}"


async def analyze_process_network_behavior(
    pid: int,
    minutes: int = 60,
    host: Optional[str] = None,
    username: Optional[str] = None,
) -> str:
    """
    Deep dive into a specific process's network behavior.

    Provides detailed analysis of network activity for a specific process,
    including connection patterns, ports accessed, remote hosts contacted,
    and behavior classification.

    Args:
        pid: Process ID to analyze
        minutes: Time window in minutes (default: 60)
        host: Optional remote host to connect to
        username: Optional SSH username (required if host is provided)

    Returns:
        Detailed analysis of process network behavior
    """
    try:
        # Validate parameters
        pid, error = validate_positive_int(pid, "PID", min_value=1)
        if error:
            return error

        minutes, error = validate_positive_int(minutes, "minutes", min_value=1, max_value=1440)
        if error:
            return error

        # Read events
        events, error = await read_event_log(DEFAULT_LOG_PATH, minutes, host, username)
        if error:
            return error

        # Filter events for this PID
        process_events = [e for e in events if e.get("process_details", {}).get("pid") == pid]

        if not process_events:
            return f"No network events found for PID {pid} in the last {minutes} minute(s)."

        # Extract process info
        first_event = process_events[0]
        command = first_event.get("process_details", {}).get("command", "unknown")

        # Analyze behavior
        unique_remote_ips = set()
        unique_remote_ports = set()
        protocols_used = Counter()
        app_protocols = Counter()
        connection_types = Counter()

        timeline = []
        suspicious_indicators = []

        for event in process_events:
            target = event.get("communication_target", {})
            remote_addr = target.get("remote_address", "unknown")
            remote_port = target.get("remote_port", 0)
            app_protocol = target.get("identified_application_protocol", "unknown")

            unique_remote_ips.add(remote_addr)
            unique_remote_ports.add(remote_port)
            protocols_used[event.get("transport_protocol", "unknown")] += 1
            app_protocols[app_protocol] += 1
            connection_types[event.get("network_ipc_mechanism", "unknown")] += 1

            # Build timeline entry
            timeline.append(
                {
                    "timestamp": event.get("timestamp", "unknown"),
                    "target": f"{remote_addr}:{remote_port}",
                    "protocol": app_protocol,
                }
            )

            # Check for suspicious indicators
            if remote_port in SUSPICIOUS_PORTS:
                suspicious_indicators.append(f"Connected to suspicious port {remote_port}")

            if remote_port > 60000:
                suspicious_indicators.append(f"Connected to high-numbered port {remote_port}")

        # Behavior classification
        behavior_class = "NORMAL"
        risk_level = "LOW"

        if suspicious_indicators:
            behavior_class = "SUSPICIOUS"
            risk_level = "HIGH"
        elif len(unique_remote_ports) > 20:
            behavior_class = "SCANNING"
            risk_level = "MEDIUM"
        elif len(unique_remote_ips) > 30:
            behavior_class = "DISTRIBUTED"
            risk_level = "MEDIUM"

        # Format output
        result = []
        result.append("=== Process Network Behavior Analysis ===")
        result.append(f"Process: {command} (PID: {pid})")
        result.append(f"Analysis Window: Last {minutes} minute(s)")
        result.append(f"Classification: {behavior_class} (Risk: {risk_level})\n")

        result.append(f"{'=' * 60}")
        result.append("SUMMARY STATISTICS")
        result.append(f"{'=' * 60}")
        result.append(f"Total Connections: {len(process_events)}")
        result.append(f"Unique Remote IPs: {len(unique_remote_ips)}")
        result.append(f"Unique Ports Accessed: {len(unique_remote_ports)}")
        result.append("")

        result.append("Connection Types:")
        for conn_type, count in connection_types.most_common():
            result.append(f"  {conn_type}: {count}")
        result.append("")

        result.append("Transport Protocols:")
        for protocol, count in protocols_used.most_common():
            result.append(f"  {protocol}: {count}")
        result.append("")

        result.append("Application Protocols:")
        for protocol, count in app_protocols.most_common(10):
            result.append(f"  {protocol}: {count}")
        result.append("")

        # Top destinations
        result.append(f"{'=' * 60}")
        result.append("TOP DESTINATIONS")
        result.append(f"{'=' * 60}")

        ip_counter = Counter(
            [e.get("communication_target", {}).get("remote_address", "unknown") for e in process_events]
        )

        for ip, count in ip_counter.most_common(10):
            result.append(f"  {ip}: {count} connection(s)")
        result.append("")

        # Top ports
        result.append("Top Ports:")
        port_counter = Counter([e.get("communication_target", {}).get("remote_port", 0) for e in process_events])

        for port, count in port_counter.most_common(10):
            result.append(f"  Port {port}: {count} connection(s)")
        result.append("")

        # Suspicious indicators
        if suspicious_indicators:
            result.append(f"{'=' * 60}")
            result.append("⚠️  SUSPICIOUS INDICATORS")
            result.append(f"{'=' * 60}")

            # Deduplicate indicators
            unique_indicators = list(set(suspicious_indicators))
            for indicator in unique_indicators[:10]:
                result.append(f"  • {indicator}")
            result.append("")

        # Timeline (recent events)
        result.append(f"{'=' * 60}")
        result.append("RECENT ACTIVITY TIMELINE (Last 20 events)")
        result.append(f"{'=' * 60}")

        for entry in timeline[-20:]:
            result.append(f"[{entry['timestamp']}] → {entry['target']} ({entry['protocol']})")

        if len(timeline) > 20:
            result.append(f"\n(Showing last 20 of {len(timeline)} events)")

        # Recommendations
        result.append(f"\n{'=' * 60}")
        result.append("RECOMMENDATIONS")
        result.append(f"{'=' * 60}")

        if behavior_class == "SUSPICIOUS":
            result.append("⚠️  This process exhibits suspicious network behavior:")
            result.append("  • Investigate process origin and legitimacy")
            result.append("  • Check for signs of malware or compromise")
            result.append("  • Consider isolating or terminating the process")
            result.append("  • Review system for other indicators of compromise")
        elif behavior_class == "SCANNING":
            result.append("⚠️  This process appears to be scanning:")
            result.append("  • Verify if scanning is authorized")
            result.append("  • Check if this is a legitimate security tool")
            result.append("  • Monitor for escalation or data exfiltration")
        elif behavior_class == "DISTRIBUTED":
            result.append("ℹ️  This process contacts many different hosts:")
            result.append("  • May be legitimate (e.g., web crawler, CDN client)")
            result.append("  • Verify business purpose")
            result.append("  • Monitor for unusual patterns")
        else:
            result.append("✓ Network behavior appears normal for this process")
            result.append("  • Continue routine monitoring")
            result.append("  • Review periodically for changes")

        return "\n".join(result)

    except Exception as e:
        return f"Error analyzing process network behavior: {str(e)}"


async def get_network_event_stats(
    minutes: int = 30,
    host: Optional[str] = None,
    username: Optional[str] = None,
) -> str:
    """
    Get summary statistics about network events.

    Provides high-level statistics and trends about network activity,
    including event counts, top processes, top ports, and timeline.

    Args:
        minutes: Time window in minutes (default: 30)
        host: Optional remote host to connect to
        username: Optional SSH username (required if host is provided)

    Returns:
        Summary statistics about network activity
    """
    try:
        # Validate minutes parameter
        minutes, error = validate_positive_int(minutes, "minutes", min_value=1, max_value=1440)
        if error:
            return error

        # Read events
        events, error = await read_event_log(DEFAULT_LOG_PATH, minutes, host, username)
        if error:
            return error

        if not events:
            return f"No network events found in the last {minutes} minute(s)."

        # Calculate statistics
        event_types = Counter()
        transport_protocols = Counter()
        processes = Counter()
        remote_ports = Counter()
        remote_ips = Counter()
        app_protocols = Counter()

        # Timeline buckets (events per minute)
        timeline_buckets = defaultdict(int)

        for event in events:
            # Event type
            event_types[event.get("network_ipc_mechanism", "unknown")] += 1

            # Transport protocol
            transport_protocols[event.get("transport_protocol", "unknown")] += 1

            # Process
            process = event.get("process_details", {})
            command = process.get("command", "unknown")
            processes[command] += 1

            # Ports and IPs
            target = event.get("communication_target", {})
            remote_ports[target.get("remote_port", 0)] += 1
            remote_ips[target.get("remote_address", "unknown")] += 1
            app_protocols[target.get("identified_application_protocol", "unknown")] += 1

            # Timeline
            timestamp_str = event.get("timestamp", "")
            event_time = parse_iso_timestamp(timestamp_str)
            if event_time:
                # Bucket by minute
                minute_key = event_time.strftime("%Y-%m-%d %H:%M")
                timeline_buckets[minute_key] += 1

        # Format output
        result = []
        result.append("=== Network Event Statistics ===")
        result.append(f"Analysis Window: Last {minutes} minute(s)")
        result.append(f"Total Events: {len(events)}\n")

        result.append(f"{'=' * 60}")
        result.append("EVENT BREAKDOWN")
        result.append(f"{'=' * 60}")

        result.append("\nEvent Types:")
        for event_type, count in event_types.most_common():
            percentage = (count / len(events)) * 100
            result.append(f"  {event_type}: {count} ({percentage:.1f}%)")

        result.append("\nTransport Protocols:")
        for protocol, count in transport_protocols.most_common():
            percentage = (count / len(events)) * 100
            result.append(f"  {protocol}: {count} ({percentage:.1f}%)")

        result.append("")

        result.append(f"{'=' * 60}")
        result.append("TOP PROCESSES (by connection count)")
        result.append(f"{'=' * 60}")

        for i, (process, count) in enumerate(processes.most_common(15), 1):
            result.append(f"{i:2d}. {process}: {count} connection(s)")

        result.append("")

        result.append(f"{'=' * 60}")
        result.append("TOP DESTINATION PORTS")
        result.append(f"{'=' * 60}")

        for i, (port, count) in enumerate(remote_ports.most_common(15), 1):
            # Try to identify the protocol
            protocol = "unknown"
            for event in events:
                target = event.get("communication_target", {})
                if target.get("remote_port") == port:
                    protocol = target.get("identified_application_protocol", "unknown")
                    break

            result.append(f"{i:2d}. Port {port} ({protocol}): {count} connection(s)")

        result.append("")

        result.append(f"{'=' * 60}")
        result.append("TOP REMOTE IP ADDRESSES")
        result.append(f"{'=' * 60}")

        for i, (ip, count) in enumerate(remote_ips.most_common(15), 1):
            result.append(f"{i:2d}. {ip}: {count} connection(s)")

        result.append("")

        result.append(f"{'=' * 60}")
        result.append("APPLICATION PROTOCOLS")
        result.append(f"{'=' * 60}")

        for protocol, count in app_protocols.most_common(15):
            percentage = (count / len(events)) * 100
            result.append(f"  {protocol}: {count} ({percentage:.1f}%)")

        # Timeline
        if timeline_buckets:
            result.append("")
            result.append(f"{'=' * 60}")
            result.append("ACTIVITY TIMELINE (Events per minute)")
            result.append(f"{'=' * 60}")

            # Sort by time
            sorted_timeline = sorted(timeline_buckets.items())

            # Show last 20 minutes of data
            for minute, count in sorted_timeline[-20:]:
                # Simple bar chart
                bar = "█" * min(count // 2, 50)
                result.append(f"{minute}  {bar} {count}")

            if len(sorted_timeline) > 20:
                result.append(f"\n(Showing last 20 minutes of {len(sorted_timeline)} minute(s) with activity)")

        return "\n".join(result)

    except Exception as e:
        return f"Error getting network event statistics: {str(e)}"
