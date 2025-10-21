#!/usr/bin/env python3
"""
Debug tool to capture SSL data and see what's being read
"""

from bcc import BPF
import ctypes

bpf_text = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    u32 tid;
    char comm[16];
    int ret_val;
    char first_bytes[32];
};

BPF_PERF_OUTPUT(events);
BPF_HASH(read_args, u64, void *);

// For SSL_read_ex: int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
int trace_ssl_read_ex_enter(struct pt_regs *ctx, void *ssl, void *buf, unsigned long num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    read_args.update(&pid_tgid, &buf);
    return 0;
}

int trace_ssl_read_ex_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void **buf_ptr = read_args.lookup(&pid_tgid);
    
    if (buf_ptr == NULL) {
        return 0;
    }
    
    void *buf = *buf_ptr;
    int ret = PT_REGS_RC(ctx);
    
    read_args.delete(&pid_tgid);
    
    if (ret <= 0) {
        return 0;
    }
    
    struct data_t data = {};
    data.pid = pid_tgid >> 32;
    data.tid = (u32)pid_tgid;
    data.ret_val = ret;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.first_bytes, sizeof(data.first_bytes), buf);
    
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

// For SSL_read: int SSL_read(SSL *ssl, void *buf, int num)
int trace_ssl_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    read_args.update(&pid_tgid, &buf);
    return 0;
}

int trace_ssl_read_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void **buf_ptr = read_args.lookup(&pid_tgid);
    
    if (buf_ptr == NULL) {
        return 0;
    }
    
    void *buf = *buf_ptr;
    int ret = PT_REGS_RC(ctx);
    
    read_args.delete(&pid_tgid);
    
    if (ret <= 0) {
        return 0;
    }
    
    struct data_t data = {};
    data.pid = pid_tgid >> 32;
    data.tid = (u32)pid_tgid;
    data.ret_val = ret;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user(&data.first_bytes, sizeof(data.first_bytes), buf);
    
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
"""

print("=" * 80)
print("SSL Data Capture Debugger")
print("=" * 80)

b = BPF(text=bpf_text)
ssl_lib = "/usr/lib/libssl.so.3"

# Attach to SSL_read_ex
try:
    b.attach_uprobe(name=ssl_lib, sym="SSL_read_ex", fn_name="trace_ssl_read_ex_enter")
    b.attach_uretprobe(name=ssl_lib, sym="SSL_read_ex", fn_name="trace_ssl_read_ex_exit")
    print(f"✓ Attached to SSL_read_ex")
except Exception as e:
    print(f"✗ Failed: {e}")

# Attach to SSL_read
try:
    b.attach_uprobe(name=ssl_lib, sym="SSL_read", fn_name="trace_ssl_read_enter")
    b.attach_uretprobe(name=ssl_lib, sym="SSL_read", fn_name="trace_ssl_read_exit")
    print(f"✓ Attached to SSL_read")
except Exception as e:
    print(f"✗ Failed: {e}")

print("\n" + "=" * 80)
print("Listening for SSL reads... (Press Ctrl+C to stop)")
print("Make an HTTPS request now!")
print("=" * 80)
print()

def print_event(cpu, data, size):
    event = b["events"].event(data)
    first_bytes = bytes(event.first_bytes).replace(b'\x00', b'')
    
    print(f"[SSL READ DETECTED]")
    print(f"  PID: {event.pid}, TID: {event.tid}")
    print(f"  Process: {event.comm.decode('utf-8', 'ignore')}")
    print(f"  Bytes read: {event.ret_val}")
    print(f"  First bytes: {first_bytes[:50]}")
    print(f"  As string: {first_bytes.decode('utf-8', 'ignore')[:50]}")
    print("-" * 80)

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n\nStopped.")



""""
This runs perfectly and trace calls:
'sudo python3 debug-ssl-data.py'
"""