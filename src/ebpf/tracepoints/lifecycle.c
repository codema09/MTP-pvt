// ═══════════════════════════════════════════════════════════════
// lifecycle.c — Thread Exit & Cleanup
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(sched, sched_process_exit) {
    if (!is_target_process()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    u64 *thread_start_ns = tid_to_thread_start.lookup(&tid);

    struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
    if (req_id_key != NULL) {
        u64 exit_time_ns = bpf_ktime_get_ns();
        u64 lifetime_ns = 0;
        if (thread_start_ns) lifetime_ns = exit_time_ns - *thread_start_ns;

        struct resource_usage_t *usage = request_resources.lookup(req_id_key);
        if (usage != NULL) {
            usage->thread_lifetime_ns = lifetime_ns;

            // Transfer CPU bursts that were accumulated before tid_to_request_id
            // was assigned (saved in tid_cpu_pre_assign by sched_switch PART 1).
            // This is the common case for threads killed while waiting on I/O.
            struct pre_assign_cpu_t *pre_cpu = tid_cpu_pre_assign.lookup(&tid);
            if (pre_cpu) {
                usage->cpu_burst_total_ns     += pre_cpu->total_ns;
                usage->cpu_cycles_total       += pre_cpu->cycles;
                usage->cpu_instructions_total += pre_cpu->instructions;
                usage->cpu_burst_count        += pre_cpu->burst_count;
                if (pre_cpu->first_cpu_burst_ns > 0 &&
                    (usage->first_cpu_burst_ns == 0 || pre_cpu->first_cpu_burst_ns < usage->first_cpu_burst_ns)) {
                    usage->first_cpu_burst_ns = pre_cpu->first_cpu_burst_ns;
                }
                if (pre_cpu->last_cpu_burst_ns > usage->last_cpu_burst_ns) {
                    usage->last_cpu_burst_ns = pre_cpu->last_cpu_burst_ns;
                }
                tid_cpu_pre_assign.delete(&tid);
            }

            // Flush the currently-open CPU burst before submitting the exit
            // event.  sched_process_exit fires while the thread is still
            // on-CPU (before the final sched_switch), so cpu_burst_start_map
            // still holds the start record for the burst that began at the
            // last switch-in.  Without this flush the burst is lost: the
            // entry is deleted below and the subsequent sched_switch has
            // nothing to accumulate.
            struct cpu_burst_start_t *burst_start = cpu_burst_start_map.lookup(&tid);
            if (burst_start) {
                u64 now_ts     = bpf_ktime_get_ns();
                u64 now_cycles = perf_cycles.perf_read(CUR_CPU_IDENTIFIER);
                u64 now_insns  = perf_instructions.perf_read(CUR_CPU_IDENTIFIER);

                u64 delta_ns     = now_ts - burst_start->ts;
                u64 delta_cycles = (now_cycles > burst_start->cycles)
                                       ? (now_cycles - burst_start->cycles) : 0;
                u64 delta_insns  = (now_insns > burst_start->instructions)
                                       ? (now_insns - burst_start->instructions) : 0;

                usage->cpu_burst_total_ns       += delta_ns;
                usage->cpu_cycles_total         += delta_cycles;
                usage->cpu_instructions_total   += delta_insns;
                usage->cpu_burst_count          += 1;
                
                if (usage->first_cpu_burst_ns == 0 || burst_start->ts < usage->first_cpu_burst_ns) {
                    usage->first_cpu_burst_ns = burst_start->ts;
                }
                if (now_ts > usage->last_cpu_burst_ns) {
                    usage->last_cpu_burst_ns = now_ts;
                }
            }

            // Transfer accumulated framework overhead into the resource record
            // so Python can read it after this TID's map entry is cleaned up.
            u64 *overhead_ptr = tid_to_overhead_ns.lookup(&tid);
            if (overhead_ptr) {
                usage->system_overhead_ns = *overhead_ptr;
            }

            struct exit_event_t ev = {};
            ev.tid = tid;
            __builtin_memcpy(ev.request_id, req_id_key->id, MAX_REQUEST_ID_LEN);
            exit_events.perf_submit(args, &ev, sizeof(ev));
        }
    }

    // Clean up all per-TID maps
    tid_to_thread_start.delete(&tid);
    tid_to_fd.delete(&pid_tgid);
    tid_to_overhead_ns.delete(&tid);
    tid_to_request_id.delete(&tid);
    tid_curr_phys.delete(&tid);
    active_sock_op.delete(&tid);
    cpu_burst_start_map.delete(&tid);
    tid_cpu_pre_assign.delete(&tid);
    tid_to_tgid.delete(&tid);

    return 0;
}

// Intercept thread spawning to propagate Request-IDs from the parent to the new child thread.
TRACEPOINT_PROBE(sched, sched_process_fork) {
    if (!is_target_process()) return 0;

    u32 parent_tid = args->parent_pid;
    u32 child_tid = args->child_pid;
    
    if (parent_tid == child_tid) return 0;

    struct request_id_key_t *req_id = tid_to_request_id.lookup(&parent_tid);
    if (req_id != NULL) {
        // Tag the newly spawned child thread with the exact same Request-ID
        tid_to_request_id.update(&child_tid, req_id);
    }

    return 0;
}
