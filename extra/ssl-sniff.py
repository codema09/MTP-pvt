#!/usr/bin/python3
from bcc import BPF
import ctypes as ct
import socket
import struct
import sys

# 1. Define the eBPF C program
# This program combines a kprobe and a uprobe to correlate
# encrypted network traffic with unencrypted user-space buffers.
# Define the eBPF C program
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define DATA_LEN 512 // Max data to capture (enough for headers)

/*
 * The data struct we'll send to user space.
 */
struct data_t {
    u64 pid_tgid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 len;
    char comm[TASK_COMM_LEN];
    char data[DATA_LEN];
};

// Perf buffer to send events to user space
BPF_PERF_OUTPUT(events);

//
// >>> CHANGE 1: Create a struct to hold both buffer and len
//
struct ssl_info_t {
    const char *buf;
    u32 len;
};

//
// >>> CHANGE 2: Change the map value to use this new struct
//
BPF_HASH(data_map, u32, struct ssl_info_t);

// Per-cpu "scratch" map for our large struct
BPF_PERCPU_ARRAY(scratch_map, struct data_t, 1);


// 1. UPROBE: Intercept SSL_write (user-space)
int trace_ssl_write(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    
    //
    // >>> CHANGE 3: Store both buf (arg 2) and len (arg 3)
    //
    struct ssl_info_t info = {};
    info.buf = (const char *)PT_REGS_PARM2(ctx);
    info.len = (u32)PT_REGS_PARM3(ctx);
    
    data_map.update(&tid, &info);
    return 0;
}

// 2. KPROBE: Intercept tcp_sendmsg (kernel-space)
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    //
    // >>> CHANGE 4: Lookup the new info struct
    //
    struct ssl_info_t *info = data_map.lookup(&tid);
    if (info == 0) {
        return 0; // Not an SSL_write, ignore
    }

    u32 zero = 0;
    struct data_t *data = scratch_map.lookup(&zero);
    if (!data) {
        return 0; // Should never happen
    }
    
    __builtin_memset(data, 0, sizeof(*data));
    
    data->pid_tgid = pid_tgid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    
    // Get IP addresses and ports
    u16 lport = 0, dport = 0;
    u32 saddr = 0, daddr = 0;
    
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&lport, sizeof(lport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    
    data->saddr = saddr;
    data->daddr = daddr;
    data->sport = lport;
    data->dport = ntohs(dport);
    
    // Use the correct length from the info struct
    data->len = info->len;
    u32 len_to_read = (data->len < DATA_LEN) ? data->len : DATA_LEN;
    
    if (info->buf) {
        bpf_probe_read_user(&data->data, len_to_read, info->buf);
    }
    
    // Submit event and clean up
    events.perf_submit(ctx, data, sizeof(*data));
    data_map.delete(&tid);
    
    return 0;
}
"""

# 2. Define Python structure matching C struct
DATA_LEN = 512 # This is the missing line

class Data(ct.Structure):
    _fields_ = [
        ("pid_tgid", ct.c_uint64),
        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),
        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("len", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("data", ct.c_char * DATA_LEN)
    ]

# 3. Callback to process events
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    
    pid = event.pid_tgid >> 32
    tid = event.pid_tgid & 0xFFFFFFFF
    
    try:
        saddr_str = socket.inet_ntoa(struct.pack("I", event.saddr))
        daddr_str = socket.inet_ntoa(struct.pack("I", event.daddr))
        
        # Decode data, replacing non-printable chars
        data_str = event.data.decode('utf-8', 'replace')
        
        # Format headers for nice printing
        headers = "\n    ".join(data_str.splitlines())
        
        print(f"PID: {pid:<7} COMM: {event.comm.decode():<16} "
              f"SRC: {saddr_str:<15}:{event.sport:<5} -> "
              f"DST: {daddr_str:<15}:{event.dport}")
        print(f"    {headers}")
        print("-" * 80)
        
    except Exception as e:
        print(f"Error processing event: {e}")

# --- Main Program ---

# 4. Load BPF program
try:
    b = BPF(text=bpf_program)
except Exception as e:
    print(f"Failed to compile or load BPF program:\n{e}")
    sys.exit(1)

# 5. Attach probes
# Find the shared library for OpenSSL
try:
    libssl_path = BPF.find_library("ssl") or BPF.find_library("ssl3")
    if not libssl_path:
        print("Could not find libssl.so; is OpenSSL installed?")
        sys.exit(1)
    
    b.attach_uprobe(name=libssl_path, sym="SSL_write", fn_name="trace_ssl_write")
    
except Exception as e:
    print(f"Failed to attach uprobe to SSL_write. Try 'sudo apt-get install -y openssl'.\n{e}")
    sys.exit(1)

# Attach kernel probe
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")

print("Tracing HTTPS traffic. Press Ctrl-C to exit.\n")
print("=" * 80)

# 6. Open perf buffer
b["events"].open_perf_buffer(print_event)

# 7. Poll for events
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nDetaching...")
    sys.exit(0)


"""
commands:
1.curl --http1.1 -b "my_cookie=hello_ebpf; another_cookie=test1234" https://www.google.com
2.
"""