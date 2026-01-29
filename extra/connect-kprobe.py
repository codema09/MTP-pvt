#!/usr/bin/python3
from bcc import BPF
import ctypes as ct
import socket
import struct

# Define the eBPF C program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

/*
 * The data struct we'll send to user space.
 */
struct conn_info_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

// Perf buffer to send events to user space
BPF_PERF_OUTPUT(connections);

/*
 * Simple hash map to track sockets between entry and return probes
 */
BPF_HASH(currsock, u32, struct sock *, 10240);

// Entry probe: capture the socket when connect is called
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    
    // Use TID as key to handle multi-threaded processes
    currsock.update(&tid, &sk);
    return 0;
}

// Return probe: capture connection details on successful connect
int trace_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    
    // Lookup the socket we stored in entry
    struct sock **skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }
    
    // Only process successful connections (ret == 0 or ret == -EINPROGRESS)
    if (ret != 0 && ret != -EINPROGRESS) {
        currsock.delete(&tid);
        return 0;
    }
    
    struct sock *sk = *skpp;
    
    // Initialize our data structure
    struct conn_info_t data = {};
    
    // Get PID and command name
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Read IP addresses and ports from socket structure
    u16 lport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;
    
    // Read local (source) address
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    data.saddr = saddr;
    
    // Read remote (destination) address  
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    data.daddr = daddr;
    
    // Read local port (already in host byte order)
    bpf_probe_read_kernel(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    data.sport = lport;
    
    // Read remote port (network byte order, needs conversion)
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    data.dport = ntohs(dport);
    
    // Submit event to user space
    connections.perf_submit(ctx, &data, sizeof(data));
    
    // Clean up
    currsock.delete(&tid);
    return 0;
}
"""

# Load BPF program
print("Loading BPF program...")
b = BPF(text=bpf_program)

# Attach kprobe and kretprobe
print("Attaching probes to tcp_v4_connect...")
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")

# Define Python structure matching C struct
class ConnInfo(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("comm", ct.c_char * 16)
    ]

# Callback to process events
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ConnInfo)).contents
    
    try:
        saddr_str = socket.inet_ntoa(struct.pack("I", event.saddr))
        daddr_str = socket.inet_ntoa(struct.pack("I", event.daddr))
        
        print(f"{event.pid:<7} {event.comm.decode('utf-8', 'replace'):<16} "
              f"{saddr_str:<15}:{event.sport:<5} -> {daddr_str:<15}:{event.dport}")
    except Exception as e:
        pass

# Open perf buffer
b["connections"].open_perf_buffer(print_event)

# Print header
print("\nTracing TCP IPv4 connections. Press Ctrl-C to exit.\n")
print(f"{'PID':<7} {'COMM':<16} {'SOURCE':<22} -> {'DESTINATION'}")
print("-" * 80)

# Poll for events
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDetaching...")
