#!/usr/bin/env python3
"""
Simple diagnostic tool to check if SSL functions are being called
"""

from bcc import BPF
from time import sleep

bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(ssl_read_count, u32, u64);
BPF_HASH(ssl_read_ex_count, u32, u64);

int count_ssl_read(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 zero = 0, *count;
    
    count = ssl_read_count.lookup_or_try_init(&pid, &zero);
    if (count) {
        (*count)++;
    }
    
    bpf_trace_printk("SSL_read called by PID %d\\n", pid);
    return 0;
}

int count_ssl_read_ex(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 zero = 0, *count;
    
    count = ssl_read_ex_count.lookup_or_try_init(&pid, &zero);
    if (count) {
        (*count)++;
    }
    
    bpf_trace_printk("SSL_read_ex called by PID %d\\n", pid);
    return 0;
}
"""

print("=" * 80)
print("SSL Function Call Debugger")
print("=" * 80)
print("Attaching to SSL functions...")

b = BPF(text=bpf_text)

ssl_lib = "/usr/lib/libssl.so.3"

try:
    b.attach_uprobe(name=ssl_lib, sym="SSL_read", fn_name="count_ssl_read")
    print(f"✓ Attached to SSL_read")
except Exception as e:
    print(f"✗ Failed to attach to SSL_read: {e}")

try:
    b.attach_uprobe(name=ssl_lib, sym="SSL_read_ex", fn_name="count_ssl_read_ex")
    print(f"✓ Attached to SSL_read_ex")
except Exception as e:
    print(f"✗ Failed to attach to SSL_read_ex: {e}")

print("\n" + "=" * 80)
print("Monitoring SSL function calls for 30 seconds...")
print("Make HTTPS requests to your server now!")
print("=" * 80)
print()

try:
    for i in range(30):
        sleep(1)
        print(f"\rWaiting... {30-i}s ", end='', flush=True)
    print("\n\n" + "=" * 80)
    print("Results:")
    print("=" * 80)
    
    print("\nSSL_read calls per PID:")
    for k, v in b["ssl_read_count"].items():
        print(f"  PID {k.value}: {v.value} calls")
    
    print("\nSSL_read_ex calls per PID:")
    for k, v in b["ssl_read_ex_count"].items():
        print(f"  PID {k.value}: {v.value} calls")
    
    if len(b["ssl_read_count"]) == 0 and len(b["ssl_read_ex_count"]) == 0:
        print("\n⚠ NO SSL CALLS DETECTED!")
        print("  This means Python might not be using SSL_read/SSL_read_ex")
        print("  or the server didn't receive any HTTPS requests")

except KeyboardInterrupt:
    print("\n\nInterrupted by user")

print("\n" + "=" * 80)

