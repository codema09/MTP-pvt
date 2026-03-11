#!/usr/bin/env python3
"""
Integrated HTTPS Sniffer with REAL-TIME Memory Logging
====================================================
Features:
1. Tracks SSL Request/Response.
2. Tracks Peak Physical Memory (RSS) per Request.
3. LOGS every single page allocation/free to 'memory_debug.log' 
   to verify exactly when memory usage spikes.

Usage: sudo python3 integrated_sniffer_debug.py -p <PID>
"""

from bcc import BPF
import socket
import struct
import ctypes
import time
import re
import os
import sys
import argparse
from datetime import datetime

# Check for root privileges
if os.geteuid() != 0:
    print("This program must be run as root!")
    sys.exit(1)

# Output Log File
LOG_FILE = open("memory_debug.log", "w")

# ═══════════════════════════════════════════════════════════════
# BPF PROGRAM
# ═══════════════════════════════════════════════════════════════

BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/sched.h>

#define MAX_HEADER_SIZE 1024
#define MAX_REQUEST_ID_LEN 64
#define TARGET_PID %s

// ═══════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════

struct alloc_args_t {
    u64 __unused;
    unsigned long pfn;
    unsigned int order;
    unsigned int gfp_flags;
};

struct free_args_t {
    u64 __unused;
    unsigned long pfn;
    unsigned int order;
};

// Event structure for the log file
struct mem_event_t {
    u64 timestamp_ns;
    u32 tid;
    u32 pid;
    u8 type; // 1=ALLOC, 0=FREE
    u64 size_bytes;
    u64 pfn;
    u64 current_total_bytes; // Snapshot of current usage
};

struct resource_usage_t {
    char request_id[MAX_REQUEST_ID_LEN];
    u32 tid;
    u64 start_time_ns;
    u64 end_time_ns;
    u64 peak_physical_bytes; // High water mark
    u8 is_complete;
};

struct ssl_event_t {
    u32 tid;
    u32 pid;
    u32 data_len;
    u8 type; // 0=READ, 1=WRITE
    char data[MAX_HEADER_SIZE];
    char comm[TASK_COMM_LEN];
};

// ═══════════════════════════════════════════════════════════════
// MAPS
// ═══════════════════════════════════════════════════════════════

// Core Tracking
BPF_HASH(tid_to_req_id, u32, struct resource_usage_t); // Active Request per TID
BPF_HASH(pfn_owner, u64, u32);                         // PFN -> TID
BPF_HASH(tid_usage, u32, u64);                         // TID -> Current Bytes

// Outputs
BPF_PERF_OUTPUT(mem_events);
BPF_PERF_OUTPUT(ssl_events);

// Scratch for SSL
BPF_HASH(ssl_args, u64, void *);
BPF_PERCPU_ARRAY(ssl_scratch, struct ssl_event_t, 1);

// ═══════════════════════════════════════════════════════════════
// HELPER: Filter PID
// ═══════════════════════════════════════════════════════════════
static inline int is_target_process() {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;
    return 1;
}

// ═══════════════════════════════════════════════════════════════
// MEMORY PROBES
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(kmem, mm_page_alloc) {
    if (!is_target_process()) return 0;

    struct alloc_args_t *ctx = (struct alloc_args_t *)args;
    u64 pfn = ctx->pfn;
    u32 order = ctx->order;
    if (pfn == 0) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 pid = pid_tgid >> 32;

    // 1. Record Ownership
    pfn_owner.update(&pfn, &tid);

    // 2. Update Current Usage
    u64 size = (1ULL << order) * 4096;
    u64 *cur_bytes_ptr = tid_usage.lookup(&tid);
    u64 cur_bytes = size;
    if (cur_bytes_ptr) {
        cur_bytes += *cur_bytes_ptr;
    }
    tid_usage.update(&tid, &cur_bytes);

    // 3. Update Request Peak (If this TID is handling a request)
    struct resource_usage_t *req = tid_to_req_id.lookup(&tid);
    if (req) {
        if (cur_bytes > req->peak_physical_bytes) {
            req->peak_physical_bytes = cur_bytes;
            // Write back to map to persist the new peak
            tid_to_req_id.update(&tid, req);
        }
    }

    // 4. Emit Event to Log
    struct mem_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.tid = tid;
    ev.pid = pid;
    ev.type = 1; // ALLOC
    ev.size_bytes = size;
    ev.pfn = pfn;
    ev.current_total_bytes = cur_bytes;
    mem_events.perf_submit(args, &ev, sizeof(ev));

    return 0;
}

TRACEPOINT_PROBE(kmem, mm_page_free) {
    struct free_args_t *ctx = (struct free_args_t *)args;
    u64 pfn = ctx->pfn;
    u32 order = ctx->order;

    // 1. Lookup Owner
    u32 *owner_tid_ptr = pfn_owner.lookup(&pfn);
    if (!owner_tid_ptr) return 0; // Not tracked
    u32 tid = *owner_tid_ptr;

    // 2. Decrement Usage
    u64 size = (1ULL << order) * 4096;
    u64 *cur_bytes_ptr = tid_usage.lookup(&tid);
    u64 cur_bytes = 0;
    if (cur_bytes_ptr) {
        if (*cur_bytes_ptr >= size) cur_bytes = *cur_bytes_ptr - size;
    }
    tid_usage.update(&tid, &cur_bytes);

    // 3. Emit Event
    // Note: We use 0 for PID here because the freeing thread might be different (GC)
    struct mem_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.tid = tid; 
    ev.pid = 0; 
    ev.type = 0; // FREE
    ev.size_bytes = size;
    ev.pfn = pfn;
    ev.current_total_bytes = cur_bytes;
    mem_events.perf_submit(args, &ev, sizeof(ev));

    // 4. Clean up
    pfn_owner.delete(&pfn);
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// SSL PROBES
// ═══════════════════════════════════════════════════════════════

static int submit_ssl(struct pt_regs *ctx, void *buf, int len, u8 type) {
    u32 zero = 0;
    struct ssl_event_t *ev = ssl_scratch.lookup(&zero);
    if (!ev) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = pid_tgid >> 32;
    ev->tid = (u32)pid_tgid;
    ev->type = type;
    
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    
    u32 copy_len = (u32)len;
    if (copy_len > MAX_HEADER_SIZE) copy_len = MAX_HEADER_SIZE;
    bpf_probe_read_user(&ev->data, copy_len, buf);
    ev->data_len = copy_len;

    ssl_events.perf_submit(ctx, ev, sizeof(*ev));
    return 0;
}

// SSL Read/Write Entry/Exit hooks...
int probe_ssl_entry(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    if (!is_target_process()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    ssl_args.update(&id, &buf);
    return 0;
}

int probe_ssl_read_exit(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    if (!is_target_process()) return 0;
    
    u64 id = bpf_get_current_pid_tgid();
    void **buf = ssl_args.lookup(&id);
    if (!buf) return 0;
    ssl_args.delete(&id);
    return submit_ssl(ctx, *buf, ret, 0); // READ
}

int probe_ssl_write_exit(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    if (!is_target_process()) return 0;
    
    u64 id = bpf_get_current_pid_tgid();
    void **buf = ssl_args.lookup(&id);
    if (!buf) return 0;
    ssl_args.delete(&id);
    return submit_ssl(ctx, *buf, ret, 1); // WRITE
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    tid_usage.delete(&tid);
    tid_to_req_id.delete(&tid);
    return 0;
}
"""

class IntegratedSniffer:
    def __init__(self, pid):
        self.pid = pid
        self.bpf = None
        self.requests = {} # {tid: {req_id, start_time, ...}}
        self.completed_requests = []
        
        # Write Header to Log
        LOG_FILE.write(f"TIMESTAMP             | TID   | EVENT | SIZE (KB) | CURRENT TID TOTAL (KB) | PFN\n")
        LOG_FILE.write("-" * 90 + "\n")

    def handle_mem_event(self, cpu, data, size):
        ev = self.bpf["mem_events"].event(data)
        
        # 1. Log to File
        ts = datetime.fromtimestamp(ev.timestamp_ns / 1e9).strftime('%H:%M:%S.%f')
        etype = "ALLOC" if ev.type == 1 else "FREE "
        size_kb = ev.size_bytes / 1024
        total_kb = ev.current_total_bytes / 1024
        
        log_line = f"{ts} | {ev.tid:<5} | {etype} | {size_kb:>9.2f} | {total_kb:>22.2f} | {ev.pfn}\n"
        LOG_FILE.write(log_line)
        LOG_FILE.flush()

    def handle_ssl_event(self, cpu, data, size):
        ev = self.bpf["ssl_events"].event(data)
        tid = ev.tid
        is_write = (ev.type == 1)
        
        # 1. READ (Request Start)
        if not is_write:
            try:
                payload = ev.data[:ev.data_len].decode('utf-8', 'ignore')
            except: return

            # Simple Request ID extraction
            req_id = "UNKNOWN"
            match = re.search(r'id=([^&\s]+)', payload)
            if match:
                req_id = match.group(1)
            
            if "GET" in payload or "POST" in payload:
                print(f"\n[Request Start] TID:{tid} ID:{req_id}")
                
                # Initialize tracking in Python
                self.requests[tid] = {
                    'id': req_id,
                    'start': time.time(),
                    'peak_mem': 0
                }

                # Initialize tracking in BPF (So kernel updates peak automatically)
                tid_map = self.bpf.get_table("tid_to_req_id")
                req_struct = tid_map.Leaf()
                req_struct.request_id = req_id.encode('utf-8')[:64]
                req_struct.tid = tid
                req_struct.peak_physical_bytes = 0 # Reset peak
                tid_map[ctypes.c_uint(tid)] = req_struct

        # 2. WRITE (Response End)
        else:
            if tid in self.requests:
                req_data = self.requests[tid]
                
                # Fetch final peak from BPF
                tid_map = self.bpf.get_table("tid_to_req_id")
                try:
                    usage = tid_map[ctypes.c_uint(tid)]
                    final_peak = usage.peak_physical_bytes
                except KeyError:
                    final_peak = 0
                
                duration = (time.time() - req_data['start']) * 1000
                
                print(f"[Request End]   TID:{tid} ID:{req_data['id']}")
                print(f"                Duration: {duration:.2f} ms")
                print(f"                Peak Physical Mem: {final_peak / 1024 / 1024:.2f} MB")
                
                # Store for summary
                self.completed_requests.append({
                    'id': req_data['id'],
                    'peak': final_peak,
                    'duration': duration
                })
                
                # Cleanup (Optional: keep in map if you want history, but prevents leak)
                # del tid_map[ctypes.c_uint(tid)] 
                del self.requests[tid]

    def run(self):
        print(f"Loading BPF for PID {self.pid}...")
        self.bpf = BPF(text=BPF_PROGRAM % self.pid)
        
        ssl_path = self.bpf.find_library("ssl")
        self.bpf.attach_uprobe(name=ssl_path, sym="SSL_read", fn_name="probe_ssl_entry")
        self.bpf.attach_uretprobe(name=ssl_path, sym="SSL_read", fn_name="probe_ssl_read_exit")
        self.bpf.attach_uprobe(name=ssl_path, sym="SSL_write", fn_name="probe_ssl_entry")
        self.bpf.attach_uretprobe(name=ssl_path, sym="SSL_write", fn_name="probe_ssl_write_exit")
        
        print(f"Logging memory events to {os.path.abspath('memory_debug.log')}")
        print("Running... (Ctrl+C to stop)")
        
        self.bpf["mem_events"].open_perf_buffer(self.handle_mem_event)
        self.bpf["ssl_events"].open_perf_buffer(self.handle_ssl_event)
        
        while True:
            try:
                self.bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                print("\n\n=== FINAL SUMMARY ===")
                for r in self.completed_requests:
                    print(f"ID: {r['id']:<15} | Peak: {r['peak']/1024/1024:.2f} MB | Time: {r['duration']:.2f} ms")
                LOG_FILE.close()
                sys.exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Integrated Sniffer with PID tracking")
    parser.add_argument("-p", "--pid", type=int, required=True, help="Target PID to track")
    args = parser.parse_args()

    IntegratedSniffer(args.pid).run()