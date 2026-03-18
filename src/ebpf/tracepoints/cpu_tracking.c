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
        // Register TID→TGID so PART 2 can check this TID in future schedule-ins.
        tid_to_tgid.update(&prev_tid, &prev_tgid);

        struct cpu_burst_start_t *start_data = cpu_burst_start_map.lookup(&prev_tid);
        if (start_data) {
            u64 delta_ns     = now_ts - start_data->ts;
            u64 delta_cycles = (now_cycles > start_data->cycles)
                                   ? (now_cycles - start_data->cycles) : 0;
            u64 delta_insns  = (now_insns > start_data->instructions)
                                   ? (now_insns - start_data->instructions) : 0;

            // Step 1: Always accumulate to the TID-keyed pre_assign buffer first.
            struct pre_assign_cpu_t *pre = tid_cpu_pre_assign.lookup(&prev_tid);
            if (pre) {
                pre->total_ns     += delta_ns;
                pre->cycles       += delta_cycles;
                pre->instructions += delta_insns;
                pre->burst_count  += 1;
                if (pre->first_cpu_burst_ns == 0 || start_data->ts < pre->first_cpu_burst_ns) {
                    pre->first_cpu_burst_ns = start_data->ts;
                }
                if (now_ts > pre->last_cpu_burst_ns) {
                    pre->last_cpu_burst_ns = now_ts;
                }
            } else {
                struct pre_assign_cpu_t new_pre = {};
                new_pre.total_ns     = delta_ns;
                new_pre.cycles       = delta_cycles;
                new_pre.instructions = delta_insns;
                new_pre.burst_count  = 1;
                new_pre.first_cpu_burst_ns = start_data->ts;
                new_pre.last_cpu_burst_ns = now_ts;
                tid_cpu_pre_assign.update(&prev_tid, &new_pre);
            }

            // Step 2: If request_id and resource entry both exist, flush pre_assign
            // into resource_map now (kernel-only write — no Python race possible).
            struct request_id_key_t *req_id = tid_to_request_id.lookup(&prev_tid);
            if (req_id) {
                struct resource_usage_t *res = request_resources.lookup(req_id);
                if (res) {
                    struct pre_assign_cpu_t *flush = tid_cpu_pre_assign.lookup(&prev_tid);
                    if (flush) {
                        res->cpu_burst_total_ns     += flush->total_ns;
                        res->cpu_cycles_total       += flush->cycles;
                        res->cpu_instructions_total += flush->instructions;
                        res->cpu_burst_count        += flush->burst_count;
                        if (flush->first_cpu_burst_ns > 0 &&
                            (res->first_cpu_burst_ns == 0 || flush->first_cpu_burst_ns < res->first_cpu_burst_ns)) {
                            res->first_cpu_burst_ns = flush->first_cpu_burst_ns;
                        }
                        if (flush->last_cpu_burst_ns > res->last_cpu_burst_ns) {
                            res->last_cpu_burst_ns = flush->last_cpu_burst_ns;
                        }
                        tid_cpu_pre_assign.delete(&prev_tid);
                    }
                }
            }

            // Step 3: Emit per-burst debug event to userspace.
            u32 zero = 0;
            struct cpu_burst_event_t *ev = cpu_burst_scratch.lookup(&zero);
            if (ev) {
                ev->tid          = prev_tid;
                ev->burst_ns     = delta_ns;
                ev->cycles       = delta_cycles;
                ev->instructions = delta_insns;
                ev->has_request_id = (req_id != NULL) ? 1 : 0;
                if (req_id) __builtin_memcpy(ev->request_id, req_id->id, MAX_REQUEST_ID_LEN);
                else __builtin_memset(ev->request_id, 0, MAX_REQUEST_ID_LEN);
                cpu_burst_events.perf_submit(args, ev, sizeof(*ev));
            }

            cpu_burst_start_map.delete(&prev_tid);
        }
    }

    // --- PART 2: Handle the INCOMING task (next) ---
    // We use args->next_pid (TID) to record burst start.
    // Check three sources: tid_to_request_id, tid_to_thread_start, tid_to_tgid.
    u32 next_tid = args->next_pid;

    int is_tracked = 0;
    if (tid_to_request_id.lookup(&next_tid)) is_tracked = 1;
    if (!is_tracked && tid_to_thread_start.lookup(&next_tid)) is_tracked = 1;
    if (!is_tracked) {
        u32 *known_tgid = tid_to_tgid.lookup(&next_tid);
        if (known_tgid) is_tracked = 1;
    }

    if (is_tracked) {
        struct cpu_burst_start_t start_data = {};
        start_data.ts           = now_ts;
        start_data.cycles       = now_cycles;
        start_data.instructions = now_insns;
        cpu_burst_start_map.update(&next_tid, &start_data);
    }

    return 0;
}
