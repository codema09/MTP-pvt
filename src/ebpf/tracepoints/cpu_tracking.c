// ═══════════════════════════════════════════════════════════════
// cpu_tracking.c — CPU Burst, Cycle & Instruction Tracking
// ═══════════════════════════════════════════════════════════════
//
// Handles BOTH switch-out (prev) and switch-in (next) in a single
// sched_switch tracepoint. This avoids kprobing finish_task_switch
// which is marked notrace on many kernels.

TRACEPOINT_PROBE(sched, sched_switch) {
    u64 now_ts = bpf_ktime_get_ns();
    u64 now_cycles = perf_cycles.perf_read(CUR_CPU_IDENTIFIER);
    u64 now_insns = perf_instructions.perf_read(CUR_CPU_IDENTIFIER);

    // --- PART 1: Handle the OUTGOING task (prev) ---
    // bpf_get_current_pid_tgid() still returns prev's context here.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 prev_tgid = pid_tgid >> 32;
    u32 prev_tid = (u32)pid_tgid;

    if (target_pids.lookup(&prev_tgid) != NULL) {
        struct cpu_burst_start_t *start_data = cpu_burst_start_map.lookup(&prev_tid);
        if (start_data) {
            u64 delta_ns = now_ts - start_data->ts;
            u64 delta_cycles = (now_cycles > start_data->cycles) ? (now_cycles - start_data->cycles) : 0;
            u64 delta_insns = (now_insns > start_data->instructions) ? (now_insns - start_data->instructions) : 0;

            struct request_id_key_t *req_id = tid_to_request_id.lookup(&prev_tid);
            if (req_id) {
                struct resource_usage_t *res = request_resources.lookup(req_id);
                if (res) {
                    res->cpu_burst_total_ns += delta_ns;
                    res->cpu_cycles_total += delta_cycles;
                    res->cpu_instructions_total += delta_insns;
                    res->cpu_burst_count += 1;
                }
            }
            cpu_burst_start_map.delete(&prev_tid);
        }
    }

    // --- PART 2: Handle the INCOMING task (next) ---
    // We use args->next_pid (TID) to record burst start.
    // Only record if this TID is tracked by us (has an entry in
    // tid_to_request_id or tid_to_thread_start).
    u32 next_tid = args->next_pid;

    int is_tracked = 0;
    struct request_id_key_t *next_req = tid_to_request_id.lookup(&next_tid);
    if (next_req) is_tracked = 1;
    if (!is_tracked) {
        u64 *next_thread_start = tid_to_thread_start.lookup(&next_tid);
        if (next_thread_start) is_tracked = 1;
    }
    if (is_tracked) {
        struct cpu_burst_start_t start_data = {};
        start_data.ts = now_ts;
        start_data.cycles = now_cycles;
        start_data.instructions = now_insns;
        cpu_burst_start_map.update(&next_tid, &start_data);
    }

    return 0;
}
