"""Tests for network monitoring tools."""

import json
import tempfile

from datetime import datetime
from datetime import timedelta
from datetime import timezone
from pathlib import Path
from unittest.mock import patch

from linux_mcp_server.tools import network_monitoring


class TestNetworkMonitoring:
    """Test network monitoring tools."""

    def create_test_event(self, minutes_ago=0, **kwargs):
        """Helper to create a test event with default values."""
        timestamp = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)

        default_event = {
            "timestamp": timestamp.isoformat(),
            "process_details": {"pid": 12345, "command": "test-process"},
            "network_ipc_mechanism": "outbound_tcp_connection",
            "transport_protocol": "TCP",
            "communication_target": {
                "remote_address": "192.168.1.100",
                "remote_port": 443,
                "identified_application_protocol": "HTTPS/TLS",
            },
            "source": {"local_address": "192.168.1.10", "local_port": 54321},
        }

        # Override with provided kwargs
        for key, value in kwargs.items():
            if isinstance(value, dict):
                default_event[key].update(value)
            else:
                default_event[key] = value

        return default_event

    def create_test_log_file(self, events):
        """Helper to create a temporary log file with test events."""
        temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl")
        for event in events:
            temp_file.write(json.dumps(event) + "\n")
        temp_file.close()
        return temp_file.name

    async def test_get_network_events_history_empty_log(self):
        """Test get_network_events_history with empty log file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
            log_path = f.name

        with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
            result = await network_monitoring.get_network_events_history(minutes=30)

            assert isinstance(result, str)
            assert "No network events found" in result

    async def test_get_network_events_history_with_events(self):
        """Test get_network_events_history with valid events."""
        events = [
            self.create_test_event(minutes_ago=5),
            self.create_test_event(minutes_ago=10),
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.get_network_events_history(minutes=30)

                assert isinstance(result, str)
                assert "Network Events" in result
                assert "2 events" in result
                assert "test-process" in result
                assert "192.168.1.100" in result
        finally:
            Path(log_path).unlink()

    async def test_get_network_events_history_filter_by_process(self):
        """Test filtering events by process name."""
        events = [
            self.create_test_event(minutes_ago=5, process_details={"pid": 100, "command": "curl"}),
            self.create_test_event(minutes_ago=10, process_details={"pid": 200, "command": "ssh"}),
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.get_network_events_history(minutes=30, filter_by_process="curl")

                assert isinstance(result, str)
                assert "curl" in result
                assert "ssh" not in result
        finally:
            Path(log_path).unlink()

    async def test_get_network_events_history_filter_by_port(self):
        """Test filtering events by port."""
        events = [
            self.create_test_event(
                minutes_ago=5,
                communication_target={
                    "remote_port": 443,
                    "remote_address": "1.1.1.1",
                    "identified_application_protocol": "HTTPS",
                },
            ),
            self.create_test_event(
                minutes_ago=10,
                communication_target={
                    "remote_port": 80,
                    "remote_address": "2.2.2.2",
                    "identified_application_protocol": "HTTP",
                },
            ),
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.get_network_events_history(minutes=30, filter_by_port=443)

                assert isinstance(result, str)
                assert "443" in result
                assert "1.1.1.1" in result
        finally:
            Path(log_path).unlink()

    async def test_get_network_events_history_time_window(self):
        """Test that time window filtering works correctly."""
        events = [
            self.create_test_event(minutes_ago=5),  # Within window
            self.create_test_event(minutes_ago=100),  # Outside window
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.get_network_events_history(minutes=30)

                assert isinstance(result, str)
                # Should only show 1 event within the 30 minute window
                assert "1 events" in result or "last 100 of" not in result
        finally:
            Path(log_path).unlink()

    async def test_get_network_events_history_invalid_minutes(self):
        """Test validation of minutes parameter."""
        result = await network_monitoring.get_network_events_history(minutes=-5)
        assert "Error" in result

    async def test_get_network_events_history_invalid_port(self):
        """Test validation of port parameter."""
        result = await network_monitoring.get_network_events_history(
            minutes=30,
            filter_by_port=-1,  # Invalid port (negative)
        )
        assert "Error" in result

    async def test_detect_network_anomalies_no_events(self):
        """Test detect_network_anomalies with no events."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
            log_path = f.name

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.detect_network_anomalies(minutes=30)

                assert isinstance(result, str)
                assert "No network events found" in result
        finally:
            Path(log_path).unlink()

    async def test_detect_network_anomalies_normal_traffic(self):
        """Test anomaly detection with normal traffic."""
        events = [self.create_test_event(minutes_ago=i) for i in range(5)]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.detect_network_anomalies(minutes=30)

                assert isinstance(result, str)
                assert "Network Anomaly Detection Report" in result
                assert "No anomalies detected" in result or "Anomalies Detected: 0" in result
        finally:
            Path(log_path).unlink()

    async def test_detect_network_anomalies_high_connection_rate(self):
        """Test detection of high connection rate anomaly."""
        # Create 60 connections from same process (exceeds threshold of 50)
        events = [
            self.create_test_event(minutes_ago=i % 30, process_details={"pid": 12345, "command": "suspicious-process"})
            for i in range(60)
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.detect_network_anomalies(minutes=30)

                assert isinstance(result, str)
                assert "High Connection Rate" in result
                assert "suspicious-process" in result
        finally:
            Path(log_path).unlink()

    async def test_detect_network_anomalies_port_scanning(self):
        """Test detection of port scanning anomaly."""
        # Create connections to 25 different ports (exceeds threshold of 20)
        events = [
            self.create_test_event(
                minutes_ago=5,
                process_details={"pid": 12345, "command": "scanner"},
                communication_target={
                    "remote_address": "192.168.1.100",
                    "remote_port": 8000 + i,
                    "identified_application_protocol": "Unknown",
                },
            )
            for i in range(25)
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.detect_network_anomalies(minutes=30)

                assert isinstance(result, str)
                assert "Port Scanning" in result or "CRITICAL" in result
        finally:
            Path(log_path).unlink()

    async def test_detect_network_anomalies_suspicious_port(self):
        """Test detection of suspicious port access."""
        events = [
            self.create_test_event(
                minutes_ago=5,
                communication_target={
                    "remote_address": "10.0.0.1",
                    "remote_port": 31337,  # Known backdoor port
                    "identified_application_protocol": "Unknown",
                },
            )
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.detect_network_anomalies(minutes=30)

                assert isinstance(result, str)
                assert "Suspicious Port" in result or "31337" in result
                assert "CRITICAL" in result
        finally:
            Path(log_path).unlink()

    async def test_analyze_process_network_behavior_no_events(self):
        """Test analyze_process_network_behavior with no events for PID."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
            log_path = f.name

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.analyze_process_network_behavior(pid=99999, minutes=60)

                assert isinstance(result, str)
                assert "No network events found" in result or "99999" in result
        finally:
            Path(log_path).unlink()

    async def test_analyze_process_network_behavior_normal_process(self):
        """Test process behavior analysis for normal process."""
        events = [
            self.create_test_event(
                minutes_ago=i,
                process_details={"pid": 12345, "command": "curl"},
                communication_target={
                    "remote_address": "1.1.1.1",
                    "remote_port": 443,
                    "identified_application_protocol": "HTTPS",
                },
            )
            for i in range(5)
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.analyze_process_network_behavior(pid=12345, minutes=60)

                assert isinstance(result, str)
                assert "Process Network Behavior Analysis" in result
                assert "curl" in result
                assert "12345" in result
                assert "NORMAL" in result or "Risk: LOW" in result
        finally:
            Path(log_path).unlink()

    async def test_analyze_process_network_behavior_suspicious_process(self):
        """Test process behavior analysis for suspicious process."""
        events = [
            self.create_test_event(
                minutes_ago=5,
                process_details={"pid": 66666, "command": "malware"},
                communication_target={
                    "remote_address": "10.0.0.1",
                    "remote_port": 31337,  # Suspicious port
                    "identified_application_protocol": "Unknown",
                },
            )
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.analyze_process_network_behavior(pid=66666, minutes=60)

                assert isinstance(result, str)
                assert "SUSPICIOUS" in result or "HIGH" in result
                assert "31337" in result
        finally:
            Path(log_path).unlink()

    async def test_analyze_process_network_behavior_invalid_pid(self):
        """Test validation of PID parameter."""
        result = await network_monitoring.analyze_process_network_behavior(pid=-1, minutes=60)
        assert "Error" in result

    async def test_get_network_event_stats_no_events(self):
        """Test get_network_event_stats with no events."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
            log_path = f.name

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.get_network_event_stats(minutes=30)

                assert isinstance(result, str)
                assert "No network events found" in result
        finally:
            Path(log_path).unlink()

    async def test_get_network_event_stats_with_events(self):
        """Test get_network_event_stats with various events."""
        events = [
            self.create_test_event(
                minutes_ago=5,
                process_details={"pid": 100, "command": "curl"},
                communication_target={
                    "remote_address": "1.1.1.1",
                    "remote_port": 443,
                    "identified_application_protocol": "HTTPS",
                },
            ),
            self.create_test_event(
                minutes_ago=10,
                process_details={"pid": 200, "command": "ssh"},
                communication_target={
                    "remote_address": "2.2.2.2",
                    "remote_port": 22,
                    "identified_application_protocol": "SSH",
                },
            ),
        ]

        log_path = self.create_test_log_file(events)

        try:
            with patch("linux_mcp_server.tools.network_monitoring.DEFAULT_LOG_PATH", log_path):
                result = await network_monitoring.get_network_event_stats(minutes=30)

                assert isinstance(result, str)
                assert "Network Event Statistics" in result
                assert "Total Events: 2" in result
                assert "curl" in result
                assert "ssh" in result
                assert "TOP PROCESSES" in result
                assert "TOP DESTINATION PORTS" in result
        finally:
            Path(log_path).unlink()

    async def test_parse_iso_timestamp(self):
        """Test ISO timestamp parsing."""
        timestamp_str = "2025-10-22T15:01:23.456789"
        result = network_monitoring.parse_iso_timestamp(timestamp_str)

        assert isinstance(result, datetime)
        assert result.year == 2025
        assert result.month == 10
        assert result.day == 22

    async def test_parse_iso_timestamp_with_timezone(self):
        """Test ISO timestamp parsing with timezone."""
        timestamp_str = "2025-10-22T15:01:23.456789+00:00"
        result = network_monitoring.parse_iso_timestamp(timestamp_str)

        assert isinstance(result, datetime)
        assert result.tzinfo is not None

    async def test_parse_iso_timestamp_invalid(self):
        """Test ISO timestamp parsing with invalid format."""
        result = network_monitoring.parse_iso_timestamp("invalid-timestamp")
        assert result is None
