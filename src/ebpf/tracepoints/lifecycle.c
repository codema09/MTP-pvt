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

    return 0;
}
