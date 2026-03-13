// ═══════════════════════════════════════════════════════════════
// maps.h — All BPF map declarations
// ═══════════════════════════════════════════════════════════════

// Registered PIDs to monitor (populated from userspace)
BPF_HASH(target_pids, u32, u32);

// Connection & Request Tracking
BPF_HASH(fd_to_conn, u32, struct conn_tuple_t);
BPF_HASH(tid_to_fd, u64, u32);
BPF_HASH(request_resources, struct request_id_key_t, struct resource_usage_t);
BPF_HASH(tid_to_request_id, u32, struct request_id_key_t);
BPF_HASH(tid_to_thread_start, u32, u64);
BPF_HASH(tid_to_overhead_ns, u32, u64);

// Memory Tracking
BPF_HASH(tid_mmap_bytes, u32, u64);
BPF_HASH(tid_mprotect_bytes, u32, u64);
BPF_HASH(pfn_owner, u64, u32);
BPF_HASH(tid_curr_phys, u32, u64);

// User History
BPF_HASH(user_request_history, struct username_key_t, struct user_history_t);

// IO Tracking
BPF_HASH(active_sock_op, u32, u8);

// CPU Burst Tracking
BPF_HASH(cpu_burst_start_map, u32, struct cpu_burst_start_t);
BPF_PERF_ARRAY(perf_cycles, NUM_CPUS);
BPF_PERF_ARRAY(perf_instructions, NUM_CPUS);

// Outgoing Connection Tracking
BPF_HASH(tcp_connect_args, u64, struct tcp_connect_args_t);

// Perf Output Buffers
BPF_PERF_OUTPUT(ssl_events);
BPF_PERF_OUTPUT(mem_events);
BPF_PERF_OUTPUT(exit_events);
BPF_PERF_OUTPUT(conn_events);

// SSL Scratch Space
BPF_HASH(ssl_read_args, u64, void *);
BPF_PERCPU_ARRAY(event_scratch, struct ssl_data_event_t, 1);
BPF_HASH(ssl_read_ex_args, u64, struct ssl_read_ex_args_t);
