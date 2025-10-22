# eBPF Network Monitoring Agent

## Overview

This directory contains the eBPF-based network monitoring agent that collects real-time network activity data from Linux systems. The agent uses eBPF (Extended Berkeley Packet Filter) to efficiently trace network connections and write events to a log file for analysis by the MCP server.

## Components

- **`agent.py`** - Main eBPF monitoring script that traces TCP/UDP connections
- **`protocols.py`** - Port-to-protocol mapping for application identification
- **`network-agent.service`** - Systemd service unit file
- **`install-agent.sh`** - Automated installation script
- **`README.md`** - This file

## Prerequisites

The agent requires the following packages on RHEL 8+:

```bash
sudo dnf install -y bcc bcc-tools kernel-devel-$(uname -r) python3
```

### Package Details

- **BCC (BPF Compiler Collection)**: Framework for eBPF programs
- **bcc-tools**: Additional BCC utilities
- **kernel-devel**: Kernel headers matching your running kernel
- **python3**: Python 3 runtime

## Installation

### Automated Installation (Recommended)

1. Copy all files from this directory to your RHEL server
2. Run the installation script:

```bash
sudo ./install-agent.sh
```

The script will:
- Verify prerequisites
- Install agent files to `/opt/network-agent/`
- Create log file at `/var/log/network-events.jsonl`
- Install and enable systemd service
- Start the agent automatically

### Manual Installation

If you prefer manual installation:

```bash
# 1. Install prerequisites
sudo dnf install -y bcc bcc-tools kernel-devel-$(uname -r) python3

# 2. Create agent directory
sudo mkdir -p /opt/network-agent
sudo cp agent.py protocols.py /opt/network-agent/
sudo chmod 755 /opt/network-agent/agent.py
sudo chmod 644 /opt/network-agent/protocols.py

# 3. Create log file
sudo touch /var/log/network-events.jsonl
sudo chmod 644 /var/log/network-events.jsonl

# 4. Install systemd service
sudo cp network-agent.service /etc/systemd/system/
sudo chmod 644 /etc/systemd/system/network-agent.service

# 5. Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable network-agent.service
sudo systemctl start network-agent.service

# 6. Verify it's running
sudo systemctl status network-agent.service
```

## Usage

### Service Management

```bash
# Check service status
sudo systemctl status network-agent.service

# View service logs (from journald)
sudo journalctl -u network-agent.service -f

# Stop the agent
sudo systemctl stop network-agent.service

# Start the agent
sudo systemctl start network-agent.service

# Restart the agent
sudo systemctl restart network-agent.service

# Disable auto-start on boot
sudo systemctl disable network-agent.service
```

### Viewing Network Events

The agent writes events to `/var/log/network-events.jsonl` in JSON Lines format (one JSON object per line):

```bash
# View recent events
tail -f /var/log/network-events.jsonl

# View and pretty-print events
tail -f /var/log/network-events.jsonl | python3 -m json.tool

# Count events by process
grep -o '"command":"[^"]*"' /var/log/network-events.jsonl | sort | uniq -c | sort -rn

# Filter events for specific process
grep '"command":"curl"' /var/log/network-events.jsonl

# Filter events for specific port
grep '"remote_port":443' /var/log/network-events.jsonl
```

## Event Format

Each event is a JSON object with the following structure:

```json
{
  "timestamp": "2025-10-22T15:01:23.456789",
  "process_details": {
    "pid": 12345,
    "command": "curl"
  },
  "network_ipc_mechanism": "outbound_tcp_connection",
  "transport_protocol": "TCP",
  "communication_target": {
    "remote_address": "104.18.30.123",
    "remote_port": 443,
    "identified_application_protocol": "HTTPS/TLS"
  },
  "source": {
    "local_address": "192.168.1.10",
    "local_port": 54321
  }
}
```

### Event Types

- **`outbound_tcp_connection`** - Process initiated TCP connection
- **`inbound_tcp_connection`** - Process accepted TCP connection
- **`outbound_udp_datagram`** - Process sent UDP packet

## Integration with MCP Server

Once the agent is running, the MCP server can analyze the events using these tools:

- **`get_network_events_history`** - View recent network events
- **`detect_network_anomalies`** - Detect suspicious patterns
- **`analyze_process_network_behavior`** - Deep dive into specific process
- **`get_network_event_stats`** - Summary statistics

Example MCP server configuration in `hosts.yaml`:

```yaml
hosts:
  - name: rhel-server
    host: bastion.r42dl.sandbox5417.opentlc.com
    username: student
    description: RHEL 8 server with eBPF network monitoring
```

## Log Rotation

To prevent the log file from growing indefinitely, set up log rotation:

```bash
sudo tee /etc/logrotate.d/network-agent > /dev/null <<EOF
/var/log/network-events.jsonl {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        systemctl reload network-agent.service > /dev/null 2>&1 || true
    endscript
}
EOF
```

This will:
- Rotate logs daily
- Keep 7 days of history
- Compress old logs
- Preserve file permissions

## Troubleshooting

### Service Won't Start

Check service logs:
```bash
sudo journalctl -u network-agent.service -n 50 --no-pager
```

Common issues:
- **Missing BCC packages**: Install with `dnf install bcc bcc-tools`
- **Kernel headers mismatch**: Install with `dnf install kernel-devel-$(uname -r)`
- **Permission denied on log file**: Check `/var/log/network-events.jsonl` permissions

### No Events Being Logged

1. Check if service is running:
   ```bash
   sudo systemctl status network-agent.service
   ```

2. Generate test traffic:
   ```bash
   curl https://www.google.com
   ```

3. Check log file:
   ```bash
   sudo tail /var/log/network-events.jsonl
   ```

4. Check for eBPF errors in journal:
   ```bash
   sudo journalctl -u network-agent.service -f
   ```

### High CPU Usage

The agent should have minimal overhead (<1% CPU typically). If you see high CPU usage:

1. Check number of active connections:
   ```bash
   ss -s
   ```

2. Reduce logging by filtering in the eBPF program (advanced)

### Log File Growing Too Large

Implement log rotation (see Log Rotation section above) or manually truncate:

```bash
# Backup and clear log
sudo cp /var/log/network-events.jsonl /var/log/network-events.jsonl.backup
sudo truncate -s 0 /var/log/network-events.jsonl
```

## Security Considerations

- The agent requires **root privileges** to attach eBPF programs to kernel functions
- The log file contains network activity data including IPs and ports
- Ensure proper file permissions on `/var/log/network-events.jsonl`
- Consider implementing access controls for the log file
- The agent uses kernel tracing, which has minimal security impact (read-only observation)

## Performance

- **CPU Overhead**: Typically <1% on busy systems
- **Memory**: ~10-20 MB
- **Log Growth**: Approximately 200-500 bytes per event
  - Light traffic: ~1-5 MB/day
  - Moderate traffic: ~10-50 MB/day
  - Heavy traffic: ~100-500 MB/day

## Uninstallation

To completely remove the agent:

```bash
# Stop and disable service
sudo systemctl stop network-agent.service
sudo systemctl disable network-agent.service

# Remove service file
sudo rm /etc/systemd/system/network-agent.service
sudo systemctl daemon-reload

# Remove agent files
sudo rm -rf /opt/network-agent

# Remove log file (optional - you may want to keep for analysis)
sudo rm /var/log/network-events.jsonl

# Remove log rotation config (if configured)
sudo rm /etc/logrotate.d/network-agent
```

## Support

For issues or questions:
- Check the main MCP server documentation
- Review systemd logs: `journalctl -u network-agent.service`
- Verify eBPF support: `uname -r` (kernel 4.4+ required)

## License

Same as linux-mcp-server project.

