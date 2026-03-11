#!/usr/bin/env python3
"""Test if mmap tracepoint is working"""

from bcc import BPF
import time

prog = """
#include <uapi/linux/ptrace.h>

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20

struct mmap_event_t {
    u32 pid;
    u32 tid;
    u64 addr;
    u64 len;
    u64 prot;
    u64 flags;
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    struct mmap_event_t evt = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;
    evt.tid = (u32)pid_tgid;
    
    // Try to capture the arguments
    evt.addr = args->addr;
    evt.len = args->len;
    evt.prot = args->prot;
    evt.flags = args->flags;
    
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    prot_str = []
    if event.prot & 0x1:
        prot_str.append("READ")
    if event.prot & 0x2:
        prot_str.append("WRITE")
    if event.prot & 0x4:
        prot_str.append("EXEC")
    
    flags_str = []
    if event.flags & 0x02:
        flags_str.append("PRIVATE")
    if event.flags & 0x20:
        flags_str.append("ANONYMOUS")
    
    print(f"[PID {event.pid} TID {event.tid}] mmap(addr=0x{event.addr:x}, len={event.len}, "
          f"prot={'|'.join(prot_str) if prot_str else 'NONE'}, "
          f"flags={'|'.join(flags_str) if flags_str else hex(event.flags)})")

print("Loading BPF program...")
b = BPF(text=prog)
b["events"].open_perf_buffer(print_event)

print("Tracing mmap calls... Press Ctrl+C to stop")
print("Run: python -c 'x = \" \" * (100 * 1024 * 1024)' in another terminal")
print()

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break

print("\nDone")
