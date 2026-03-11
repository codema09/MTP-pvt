# #!/usr/bin/python3
# from bcc import BPF
# import time
# import sys

# # 0. ARGUMENT PARSING
# target_pid = 21632  # Replace with your PID or use sys.argv
# if len(sys.argv) > 1:
#     target_pid = int(sys.argv[1])

# print(f"Attaching BPF probes to PID: {target_pid}...")

# bpf_source = f"""
# #include <linux/sched.h>

# // -----------------------------------------------------------------------------
# // SHARED STATE
# // -----------------------------------------------------------------------------
# BPF_ARRAY(current_state, s64, 3);

# static inline int should_trace() {{
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#      u32 pid = pid_tgid >> 32;
#     if (pid != {target_pid}) return 0;
#     return 1;
# }}

# // -----------------------------------------------------------------------------
# // PROBES
# // -----------------------------------------------------------------------------
# TRACEPOINT_PROBE(kmem, mm_page_alloc) {{
#     if (!should_trace()) return 0;

#     // We can now access args->order because we defined the struct above
#     u64 order = args->order; 
#     u64 size_bytes = (1ULL << order) * 4096;
    
#     // Increment
#     current_state.increment(0, size_bytes);
#     if (order >= 9) current_state.increment(1, 1);
#     else            current_state.increment(2, 1);
    
#     return 0;
# }}

# TRACEPOINT_PROBE(kmem, mm_page_free) {{
#     if (!should_trace()) return 0;

#     u64 order = args->order;
#     s64 size_bytes = (1ULL << order) * 4096;

#     // Decrement (Add negative)
#     current_state.increment(0, -size_bytes);
#     if (order >= 9) current_state.increment(1, -1);
#     else            current_state.increment(2, -1);

#     return 0;
# }}
# """

# # 2. COMPILE AND LOAD
# try:
#     b = BPF(text=bpf_source)
# except Exception as e:
#     print("Compilation failed! details:")
#     print(e)
#     sys.exit(1)

# print(f"{'TIME':<8} {'CURRENT MEM (MB)':<18} {'HUGE PAGES HELD':<18} {'SMALL PAGES HELD':<18}")
# print("-" * 70)

# # 3. MONITOR LOOP
# try:
#     while True:
#         time.sleep(5)
#         state = b["current_state"]
        
#         current_bytes = state[0].value
#         current_huge  = state[1].value
#         current_small = state[2].value
        
#         current_mb = current_bytes / (1024 * 1024)
#         cur_time = time.strftime("%H:%M:%S")
        
#         print(f"{cur_time:<8} {current_mb:<18.2f} {current_huge:<18} {current_small:<18}")

# except KeyboardInterrupt:
#     print("\nDetaching...")


#___________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________#

# #!/usr/bin/python3
# from bcc import BPF
# import time
# import sys

# # 0. ARGUMENT PARSING
# target_pid = 0
# if len(sys.argv) > 1:
#     target_pid = int(sys.argv[1])

# print(f"Tracking PFN Ownership. Target PID: {target_pid if target_pid else 'ALL'}")

# bpf_source = f"""
# #include <linux/sched.h>

# // -----------------------------------------------------------------------------
# // 1. MANUAL STRUCT DEFINITIONS
# // -----------------------------------------------------------------------------
# // We define our OWN structs to match the raw kernel binary layout.
# // This bypasses BCC's internal header conflicts.

# struct alloc_args_t {{
#     u64 __unused;
#     unsigned long pfn;    // Offset 8: The Page Frame Number
#     unsigned int order;   // Offset 16: Order
#     unsigned int gfp_flags;
# }};

# struct free_args_t {{
#     u64 __unused;
#     unsigned long pfn;
#     unsigned int order;
# }};

# // -----------------------------------------------------------------------------
# // 2. MAPS
# // -----------------------------------------------------------------------------
# // Key: PFN (u64) -> Value: TID (u32)
# BPF_HASH(pfn_to_tid, u64, u32);

# static inline int should_trace() {{
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 pid = pid_tgid >> 32;
#     if ({target_pid} != 0 && pid != {target_pid}) return 0;
#     return 1;
# }}

# // -----------------------------------------------------------------------------
# // 3. PROBES
# // -----------------------------------------------------------------------------

# TRACEPOINT_PROBE(kmem, mm_page_alloc) {{
#     if (!should_trace()) return 0;

#     // Cast the generic 'args' to our custom struct
#     struct alloc_args_t *ctx = (struct alloc_args_t *)args;

#     u64 pfn = ctx->pfn;
    
#     // Valid PFN check
#     if (pfn == 0) return 0;

#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 tid = (u32)pid_tgid;

#     pfn_to_tid.update(&pfn, &tid);
    
#     return 0;
# }}

# TRACEPOINT_PROBE(kmem, mm_page_free) {{
#     // Note: We don't filter PID on free (garbage collector might be different thread)
    
#     struct free_args_t *ctx = (struct free_args_t *)args;
#     u64 pfn = ctx->pfn;

#     // If we were tracking this PFN, delete it
#     if (pfn_to_tid.lookup(&pfn)) {{
#         pfn_to_tid.delete(&pfn);
#     }}

#     return 0;
# }}
# """

# # 2. COMPILE AND LOAD
# try:
#     b = BPF(text=bpf_source)
# except Exception as e:
#     print("-" * 60)
#     print("COMPILATION ERROR!")
#     print("Your kernel might have a slightly different tracepoint format.")
#     print("Please run this command to check the exact format:")
#     print("sudo cat /sys/kernel/debug/tracing/events/kmem/mm_page_alloc/format")
#     print("-" * 60)
#     print(e)
#     sys.exit(1)

# print(f"{'TIME':<8} {'Active Pages (PFNs)':<20} {'Sample TID':<15}")
# print("-" * 50)

# # 3. MONITOR LOOP
# page_map = b["pfn_to_tid"]

# try:
#     while True:
#         time.sleep(2)
#         count = len(page_map)
        
#         sample_tid = "N/A"
#         if count > 0:
#             for k, v in page_map.items():
#                 sample_tid = v.value
#                 break
            
#         cur_time = time.strftime("%H:%M:%S")
#         print(f"{cur_time:<8} {count:<20} {sample_tid:<15}")

# except KeyboardInterrupt:
#     print("\nDetaching...")
#___________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________________#



#!/usr/bin/python3
from bcc import BPF
import time
import sys

# 0. ARGUMENT PARSING
target_pid = 0
if len(sys.argv) > 1:
    target_pid = int(sys.argv[1])

print(f"Tracking Per-Thread Memory. Target PID: {target_pid if target_pid else 'ALL'}")

bpf_source = f"""
#include <linux/sched.h>

// -----------------------------------------------------------------------------
// 1. DATA STRUCTURES
// -----------------------------------------------------------------------------

// Tracepoint Argument Layouts (Manual Definition for PFN support)
struct alloc_args_t {{
    u64 __unused;
    unsigned long pfn;
    unsigned int order;
    unsigned int gfp_flags;
}};

struct free_args_t {{
    u64 __unused;
    unsigned long pfn;
    unsigned int order;
}};

// The Stats we want to track per thread
struct thread_stats_t {{
    u64 normal_pages; // Order < 9
    u64 huge_pages;   // Order >= 9
    u64 total_bytes;
}};

// -----------------------------------------------------------------------------
// 2. MAPS
// -----------------------------------------------------------------------------

// Map 1: Lookup who owns a physical page (PFN -> TID)
BPF_HASH(pfn_owner, u64, u32);

// Map 2: Aggregated stats per thread (TID -> Stats)
BPF_HASH(tid_stats, u32, struct thread_stats_t);

static inline int should_trace() {{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if ({target_pid} != 0 && pid != {target_pid}) return 0;
    return 1;
}}

// -----------------------------------------------------------------------------
// 3. ALLOC LOGIC
// -----------------------------------------------------------------------------
TRACEPOINT_PROBE(kmem, mm_page_alloc) {{
    if (!should_trace()) return 0;

    struct alloc_args_t *ctx = (struct alloc_args_t *)args;
    u64 pfn = ctx->pfn;
    u32 order = ctx->order;
    
    if (pfn == 0) return 0;

    // 1. Identify the Thread
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    // 2. Record Ownership (So we know who to subtract from later)
    pfn_owner.update(&pfn, &tid);

    // 3. Update Thread Stats
    struct thread_stats_t *stats, zero_stats = {{}};
    stats = tid_stats.lookup_or_try_init(&tid, &zero_stats);
    
    if (stats) {{
        u64 size = (1ULL << order) * 4096;
        stats->total_bytes += size;
        
        if (order >= 9) {{
            stats->huge_pages += 1;
        }} else {{
            stats->normal_pages += 1;
        }}
    }}
    
    return 0;
}}

// -----------------------------------------------------------------------------
// 4. FREE LOGIC
// -----------------------------------------------------------------------------
TRACEPOINT_PROBE(kmem, mm_page_free) {{
    struct free_args_t *ctx = (struct free_args_t *)args;
    u64 pfn = ctx->pfn;
    u32 order = ctx->order;

    // 1. Who owned this page?
    u32 *owner_tid_ptr = pfn_owner.lookup(&pfn);
    
    // If we weren't tracking this page, ignore it (allocated before script started)
    if (!owner_tid_ptr) return 0;

    u32 owner_tid = *owner_tid_ptr;

    // 2. Decrement the OWNER'S stats (even if a different thread is freeing it)
    struct thread_stats_t *stats = tid_stats.lookup(&owner_tid);
    
    if (stats) {{
        u64 size = (1ULL << order) * 4096;
        
        // Prevent underflow (sanity check)
        if (stats->total_bytes >= size) 
            stats->total_bytes -= size;
            
        if (order >= 9) {{
            if (stats->huge_pages > 0) stats->huge_pages -= 1;
        }} else {{
            if (stats->normal_pages > 0) stats->normal_pages -= 1;
        }}
    }}

    // 3. Forget the page
    pfn_owner.delete(&pfn);

    return 0;
}}
"""

# 2. COMPILE
try:
    b = BPF(text=bpf_source)
except Exception as e:
    print("Compilation Error!")
    print(e)
    sys.exit(1)

print(f"{'TIME':<8} {'TID':<8} {'NORMAL PAGES':<15} {'HUGE PAGES':<15} {'TOTAL MEM (MB)':<15}")
print("-" * 65)

# 3. MONITOR LOOP
stats_map = b["tid_stats"]

try:
    while True:
        time.sleep(2)
        
        # Clear screen to make it a dashboard (optional, remove check to scroll)
        # print("\033[H\033[J", end="") 
        # print(f"{'TIME':<8} {'TID':<8} {'NORMAL PAGES':<15} {'HUGE PAGES':<15} {'TOTAL MEM (MB)':<15}")
        # print("-" * 65)

        cur_time = time.strftime("%H:%M:%S")
        
        # Iterate over the map
        # Note: items() makes a copy, so it's safe to iterate
        for k, v in stats_map.items():
            tid = k.value
            normal = v.normal_pages
            huge = v.huge_pages
            total_mb = v.total_bytes / (1024 * 1024)
            
            # Filter out empty entries to reduce noise
            if v.total_bytes > 0:
                print(f"{cur_time:<8} {tid:<8} {normal:<15} {huge:<15} {total_mb:<15.2f}")
        
        print("") # Newline separator

except KeyboardInterrupt:
    print("\nDetaching...")
