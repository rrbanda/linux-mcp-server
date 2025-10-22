#!/usr/bin/python3
#
# agent.py (v6) - RHEL 8 Process Network Analysis Agent
#
# This version writes JSON events to /var/log/network-events.jsonl
# instead of printing to stdout, making it suitable for systemd service deployment.
#
# USAGE: sudo python3 agent.py
#

import json
import socket
import struct
import sys
import traceback

from datetime import datetime

from bcc import BPF
from protocols import get_protocol


# Configuration
LOG_FILE = "/var/log/network-events.jsonl"

# The eBPF program - using syscall tracepoints for reliable data capture
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/in.h>
#include <linux/in6.h>

enum event_type {
    EVENT_TCP_CONNECT,
    EVENT_TCP_ACCEPT,
    EVENT_UDP_SEND,
};

// Separate structures for IPv4 and IPv6 like official BCC tools
struct ipv4_data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct ipv6_data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    enum event_type type;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
};

BPF_PERF_OUTPUT(ipv4_events);
BPF_PERF_OUTPUT(ipv6_events);

// Hash map to store PID+comm for sockets (key=sock pointer)
struct pid_comm_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};
BPF_HASH(sock_info, u64, struct pid_comm_t);

// Store PID on tcp_v4_connect ENTRY
int trace_tcp_v4_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 sock_addr = (u64)sk;
    struct pid_comm_t info = {};
    
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    
    sock_info.update(&sock_addr, &info);
    return 0;
}

// Store PID on tcp_v6_connect ENTRY
int trace_tcp_v6_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 sock_addr = (u64)sk;
    struct pid_comm_t info = {};
    
    info.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    
    sock_info.update(&sock_addr, &info);
    return 0;
}

// Hook tcp_set_state to catch when connection becomes ESTABLISHED
int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    // Only care about ESTABLISHED state
    if (state != TCP_ESTABLISHED)
        return 0;
    
    u64 sock_addr = (u64)sk;
    struct pid_comm_t *info = sock_info.lookup(&sock_addr);
    
    // If we don't have stored info, skip (might be inbound connection)
    if (info == NULL)
        return 0;
    
    u16 family = sk->__sk_common.skc_family;
    
    // Clean up hash entry first
    sock_info.delete(&sock_addr);
    
    if (family == AF_INET) {
        // IPv4 connection
        struct ipv4_data_t data4 = {};
        data4.pid = info->pid;
        __builtin_memcpy(&data4.comm, info->comm, TASK_COMM_LEN);
        data4.ts = bpf_ktime_get_ns();
        data4.type = EVENT_TCP_CONNECT;
        
        // Direct assignment for IPv4 addresses
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.sport = sk->__sk_common.skc_num;
        data4.dport = sk->__sk_common.skc_dport;
        
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        // IPv6 connection
        struct ipv6_data_t data6 = {};
        data6.pid = info->pid;
        __builtin_memcpy(&data6.comm, info->comm, TASK_COMM_LEN);
        data6.ts = bpf_ktime_get_ns();
        data6.type = EVENT_TCP_CONNECT;
        
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &sk->__sk_common.skc_v6_daddr);
        data6.sport = sk->__sk_common.skc_num;
        data6.dport = sk->__sk_common.skc_dport;
        
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    
    return 0;
}

// Accept tracking
int trace_inet_csk_accept_return(struct pt_regs *ctx) {
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    
    if (newsk == NULL)
        return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 family = newsk->__sk_common.skc_family;
    
    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.pid = pid;
        data4.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&data4.comm, sizeof(data4.comm));
        data4.type = EVENT_TCP_ACCEPT;
        
        data4.saddr = newsk->__sk_common.skc_rcv_saddr;
        data4.daddr = newsk->__sk_common.skc_daddr;
        data4.sport = newsk->__sk_common.skc_num;
        data4.dport = newsk->__sk_common.skc_dport;
        
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {};
        data6.pid = pid;
        data6.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&data6.comm, sizeof(data6.comm));
        data6.type = EVENT_TCP_ACCEPT;
        
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &newsk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &newsk->__sk_common.skc_v6_daddr);
        data6.sport = newsk->__sk_common.skc_num;
        data6.dport = newsk->__sk_common.skc_dport;
        
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    
    return 0;
}

// UDP tracking
int trace_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    if (sk == NULL)
        return 0;
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u16 family = sk->__sk_common.skc_family;
    
    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.pid = pid;
        data4.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&data4.comm, sizeof(data4.comm));
        data4.type = EVENT_UDP_SEND;
        
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.sport = sk->__sk_common.skc_num;
        data4.dport = sk->__sk_common.skc_dport;
        
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {};
        data6.pid = pid;
        data6.ts = bpf_ktime_get_ns();
        bpf_get_current_comm(&data6.comm, sizeof(data6.comm));
        data6.type = EVENT_UDP_SEND;
        
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &sk->__sk_common.skc_v6_daddr);
        data6.sport = sk->__sk_common.skc_num;
        data6.dport = sk->__sk_common.skc_dport;
        
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    
    return 0;
}
"""


def process_ipv4_event(cpu, data, size):
    """
    Callback for IPv4 events - uses u32 for addresses
    """
    try:
        event = b["ipv4_events"].event(data)

        ipc_mechanism = "unknown"
        transport_protocol = "unknown"
        identified_app_protocol = "unknown"

        # Ports from kernel are in network byte order, convert to host order
        sport = event.sport  # skc_num is already in host byte order
        dport = socket.ntohs(event.dport) if event.dport else 0

        if event.type == 0:  # EVENT_TCP_CONNECT
            ipc_mechanism = "outbound_tcp_connection"
            transport_protocol = "TCP"
            identified_app_protocol = get_protocol(dport)
        elif event.type == 1:  # EVENT_TCP_ACCEPT
            ipc_mechanism = "inbound_tcp_connection"
            transport_protocol = "TCP"
            identified_app_protocol = get_protocol(sport)
        elif event.type == 2:  # EVENT_UDP_SEND
            ipc_mechanism = "outbound_udp_datagram"
            transport_protocol = "UDP"
            identified_app_protocol = get_protocol(dport)

        # Convert IPv4 addresses (u32) to dotted notation
        saddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.saddr))
        daddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", event.daddr))

        output = {
            "timestamp": datetime.now().isoformat(),
            "process_details": {
                "pid": event.pid,
                "command": event.comm.decode("utf-8", "replace"),
            },
            "network_ipc_mechanism": ipc_mechanism,
            "transport_protocol": transport_protocol,
            "communication_target": {
                "remote_address": daddr,
                "remote_port": dport,
                "identified_application_protocol": identified_app_protocol,
            },
            "source": {
                "local_address": saddr,
                "local_port": sport,
            },
        }

        # Write to log file (one JSON object per line)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(output) + "\n")

    except Exception as e:
        # Log errors to stderr (captured by systemd)
        print(f"Error processing IPv4 event: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)


def process_ipv6_event(cpu, data, size):
    """
    Callback for IPv6 events - uses u128 for addresses
    """
    try:
        event = b["ipv6_events"].event(data)

        ipc_mechanism = "unknown"
        transport_protocol = "unknown"
        identified_app_protocol = "unknown"

        # Ports from kernel are in network byte order, convert to host order
        sport = event.sport  # skc_num is already in host byte order
        dport = socket.ntohs(event.dport) if event.dport else 0

        if event.type == 0:  # EVENT_TCP_CONNECT
            ipc_mechanism = "outbound_tcp_connection"
            transport_protocol = "TCP"
            identified_app_protocol = get_protocol(dport)
        elif event.type == 1:  # EVENT_TCP_ACCEPT
            ipc_mechanism = "inbound_tcp_connection"
            transport_protocol = "TCP"
            identified_app_protocol = get_protocol(sport)
        elif event.type == 2:  # EVENT_UDP_SEND
            ipc_mechanism = "outbound_udp_datagram"
            transport_protocol = "UDP"
            identified_app_protocol = get_protocol(dport)

        # Convert IPv6 addresses (u128 as ctypes array) to string
        saddr_bytes = struct.pack("QQ", event.saddr[0], event.saddr[1])
        daddr_bytes = struct.pack("QQ", event.daddr[0], event.daddr[1])
        saddr = socket.inet_ntop(socket.AF_INET6, saddr_bytes)
        daddr = socket.inet_ntop(socket.AF_INET6, daddr_bytes)

        output = {
            "timestamp": datetime.now().isoformat(),
            "process_details": {
                "pid": event.pid,
                "command": event.comm.decode("utf-8", "replace"),
            },
            "network_ipc_mechanism": ipc_mechanism,
            "transport_protocol": transport_protocol,
            "communication_target": {
                "remote_address": daddr,
                "remote_port": dport,
                "identified_application_protocol": identified_app_protocol,
            },
            "source": {
                "local_address": saddr,
                "local_port": sport,
            },
        }

        # Write to log file (one JSON object per line)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(output) + "\n")

    except Exception as e:
        # Log errors to stderr (captured by systemd)
        print(f"Error processing IPv6 event: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)


# Main execution
if __name__ == "__main__":
    print("Starting RHEL Process Network Agent (v6)...", file=sys.stderr)
    print(f"Logging events to: {LOG_FILE}", file=sys.stderr)
    print("Monitoring for network activity. Press Ctrl+C to exit.", file=sys.stderr)

    # Ensure log file is writable
    try:
        with open(LOG_FILE, "a") as f:
            pass
    except Exception as e:
        print(f"ERROR: Cannot write to {LOG_FILE}: {e}", file=sys.stderr)
        print("Please ensure the agent has permission to write to this location.", file=sys.stderr)
        sys.exit(1)

    try:
        b = BPF(text=bpf_program)
        # TCP outbound: Store PID on entry, emit on ESTABLISHED
        b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect_entry")
        b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_tcp_v6_connect_entry")
        b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")
        # TCP inbound: Capture on accept return
        b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_inet_csk_accept_return")
        # UDP: Capture at sendmsg
        b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")

        # Open both IPv4 and IPv6 perf buffers
        b["ipv4_events"].open_perf_buffer(process_ipv4_event)
        b["ipv6_events"].open_perf_buffer(process_ipv6_event)

        print("Agent started successfully. Monitoring IPv4 and IPv6 traffic...", file=sys.stderr)

        while True:
            b.perf_buffer_poll()

    except KeyboardInterrupt:
        print("\nAgent stopped.", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
