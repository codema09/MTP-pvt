#!/usr/bin/env python3
"""
Resource Usage Tracker - eBPF Module
=====================================
Tracks CPU cycles, memory usage, and time taken for each HTTPS request.
Tagged by unique request ID extracted from HTTP headers.

Can be loaded independently or integrated with main sniffer.
"""

# eBPF program for resource tracking
RESOURCE_TRACKER_BPF = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_REQUEST_ID_LEN 64

// Key structure for request ID
struct request_id_key_t {
    char id[MAX_REQUEST_ID_LEN];
};

// Resource usage structure
struct resource_usage_t {
    char request_id[MAX_REQUEST_ID_LEN];  // Unique request identifier
    u32 tid;                               // Thread handling this request
    u64 start_time_ns;                     // Request start time (nanoseconds)
    u64 end_time_ns;                       // Request end time
    u64 cpu_cycles_start;                  // CPU cycles at start
    u64 cpu_cycles_end;                    // CPU cycles at end
    u64 duration_ns;                       // Total duration
    u64 cpu_cycles_used;                   // CPU cycles consumed
    u32 memory_kb;                         // Memory used (approximate)
    u8 is_complete;                        // 1 if request completed
};

// PRIMARY MAP: Request ID → Resource Usage
BPF_HASH(request_resources, struct request_id_key_t, struct resource_usage_t);

// Temporary: TID → Request ID (for tracking)
BPF_HASH(tid_to_request_id, u32, struct request_id_key_t);

// Helper: Get CPU cycles
static inline u64 get_cpu_cycles() {
    u64 cycles = bpf_ktime_get_ns();  // Approximation using ktime
    return cycles;
}

// Helper: Get memory usage for current task
static inline u32 get_memory_usage_kb() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Get RSS (Resident Set Size) from task's mm_struct
    struct mm_struct *mm;
    bpf_probe_read_kernel(&mm, sizeof(mm), &task->mm);
    
    if (mm == NULL) {
        return 0;
    }
    
    // Note: Actual RSS calculation is complex and version-dependent
    // For simplicity, we return a placeholder
    // In production, you'd need to read mm->rss_stat
    return 0;  // TODO: Implement proper RSS reading
}

// Called when a request starts (triggered by first SSL_read for a request)
int start_request_tracking(u32 tid, char request_id[MAX_REQUEST_ID_LEN]) {
    struct resource_usage_t usage = {
        .tid = tid,
        .start_time_ns = bpf_ktime_get_ns(),
        .cpu_cycles_start = get_cpu_cycles(),
        .memory_kb = get_memory_usage_kb(),
        .is_complete = 0,
    };
    
    // Copy request ID
    bpf_probe_read_kernel_str(usage.request_id, MAX_REQUEST_ID_LEN, request_id);
    
    // Store by request ID
    request_resources.update(&request_id, &usage);
    
    // Track TID → Request ID for later completion
    tid_to_request_id.update(&tid, &request_id);
    
    return 0;
}

// Called when a request completes (triggered by response or connection close)
int end_request_tracking(u32 tid) {
    // Get request ID for this thread
    char (*request_id_ptr)[MAX_REQUEST_ID_LEN] = tid_to_request_id.lookup(&tid);
    if (request_id_ptr == NULL) {
        return 0;  // Not tracking this thread
    }
    
    char request_id[MAX_REQUEST_ID_LEN];
    bpf_probe_read_kernel(request_id, MAX_REQUEST_ID_LEN, request_id_ptr);
    
    // Get existing usage record
    struct resource_usage_t *usage = request_resources.lookup(&request_id);
    if (usage == NULL) {
        return 0;
    }
    
    // Update with end metrics
    usage->end_time_ns = bpf_ktime_get_ns();
    usage->cpu_cycles_end = get_cpu_cycles();
    usage->duration_ns = usage->end_time_ns - usage->start_time_ns;
    usage->cpu_cycles_used = usage->cpu_cycles_end - usage->cpu_cycles_start;
    usage->is_complete = 1;
    
    // Update map
    request_resources.update(&request_id, usage);
    
    // Clean up TID mapping
    tid_to_request_id.delete(&tid);
    
    return 0;
}
"""

class ResourceTracker:
    """Manages resource usage tracking for HTTPS requests"""
    
    def __init__(self, bpf_instance):
        """
        Initialize with an existing BPF instance that has loaded RESOURCE_TRACKER_BPF
        """
        self.bpf = bpf_instance
    
    def start_tracking(self, tid, request_id):
        """Start tracking resources for a request"""
        try:
            # Call eBPF helper
            tid_c = self.bpf["tid_to_request_id"].Key(tid)
            req_id_bytes = request_id.encode('utf-8')[:63] + b'\x00'
            
            # Create resource usage entry
            usage = self.bpf["request_resources"].Leaf()
            usage.tid = tid
            usage.start_time_ns = 0  # Will be set by eBPF
            usage.is_complete = 0
            
            # Store request ID
            req_id_arr = (ctypes.c_char * 64)()
            req_id_arr.value = req_id_bytes
            usage.request_id = req_id_arr
            
            print(f"  [→] Started tracking: {request_id} (TID={tid})")
            
        except Exception as e:
            print(f"  [⚠] Error starting tracking: {e}")
    
    def get_resource_usage(self, request_id):
        """Get resource usage for a specific request ID"""
        try:
            request_resources = self.bpf.get_table("request_resources")
            
            req_id_bytes = request_id.encode('utf-8')[:63] + b'\x00'
            req_id_key = (ctypes.c_char * 64)()
            req_id_key.value = req_id_bytes
            
            usage = request_resources[req_id_key]
            
            return {
                'request_id': usage.request_id.decode('utf-8').rstrip('\x00'),
                'tid': usage.tid,
                'duration_ns': usage.duration_ns,
                'duration_ms': usage.duration_ns / 1_000_000,
                'cpu_cycles_used': usage.cpu_cycles_used,
                'memory_kb': usage.memory_kb,
                'is_complete': usage.is_complete
            }
        except Exception as e:
            return None
    
    def display_all_resources(self):
        """Display resource usage for all tracked requests"""
        print("\n" + "=" * 80)
        print("RESOURCE USAGE BY REQUEST")
        print("=" * 80)
        
        request_resources = self.bpf.get_table("request_resources")
        
        if len(request_resources) == 0:
            print("  No requests tracked yet.")
        else:
            print(f"  Total requests tracked: {len(request_resources)}\n")
            
            for req_id_key, usage in request_resources.items():
                request_id = req_id_key.value.decode('utf-8', errors='ignore').rstrip('\x00')
                
                if not request_id:
                    continue
                
                duration_ms = usage.duration_ns / 1_000_000.0
                status = "✓ Complete" if usage.is_complete else "⏳ In Progress"
                
                print(f"  Request ID: {request_id}")
                print(f"    Status:       {status}")
                print(f"    Thread TID:   {usage.tid}")
                print(f"    Duration:     {duration_ms:.2f} ms")
                print(f"    CPU Cycles:   {usage.cpu_cycles_used:,}")
                if usage.memory_kb > 0:
                    print(f"    Memory:       {usage.memory_kb} KB")
                print()
        
        print("=" * 80)


# For standalone testing
if __name__ == "__main__":
    from bcc import BPF
    import ctypes
    
    print("Resource Tracker - Standalone Test")
    print("=" * 80)
    print("Loading eBPF program...")
    
    bpf = BPF(text=RESOURCE_TRACKER_BPF)
    tracker = ResourceTracker(bpf)
    
    print("✓ Resource tracker loaded")
    print("\nThis module is meant to be integrated with the main sniffer.")
    print("Use: from resource_tracker import RESOURCE_TRACKER_BPF, ResourceTracker")

