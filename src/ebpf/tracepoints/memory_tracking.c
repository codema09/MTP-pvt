// ═══════════════════════════════════════════════════════════════
// memory_tracking.c — Virtual & Physical Memory Tracking
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    if (!is_target_process()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    if ((args->prot & (PROT_READ|PROT_WRITE)) != (PROT_READ|PROT_WRITE)) return 0;
    if ((args->flags & (MAP_PRIVATE|MAP_ANONYMOUS)) != (MAP_PRIVATE|MAP_ANONYMOUS)) return 0;

    u64 *existing_bytes = tid_mmap_bytes.lookup(&tid);
    if (existing_bytes) {
        u64 updated = *existing_bytes + args->len;
        tid_mmap_bytes.update(&tid, &updated);
    } else {
        u64 initial = args->len;
        tid_mmap_bytes.update(&tid, &initial);
    }

    struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
    if (req_id_key != NULL) {
        struct resource_usage_t *usage = request_resources.lookup(req_id_key);
        if (usage != NULL) {
            usage->mmap_bytes += args->len;
        }
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    if (!is_target_process()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    if ((args->prot & (PROT_READ|PROT_WRITE)) != (PROT_READ|PROT_WRITE)) return 0;

    u64 *existing_bytes = tid_mprotect_bytes.lookup(&tid);
    if (existing_bytes) {
        u64 updated = *existing_bytes + args->len;
        tid_mprotect_bytes.update(&tid, &updated);
    } else {
        u64 initial = args->len;
        tid_mprotect_bytes.update(&tid, &initial);
    }

    struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
    if (req_id_key != NULL) {
        struct resource_usage_t *usage = request_resources.lookup(req_id_key);
        if (usage != NULL) {
            usage->mprotect_bytes += args->len;
        }
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// Physical Page Allocation / Free Tracking
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

    pfn_owner.update(&pfn, &tid);

    u64 size = (1ULL << order) * 4096;
    u64 *cur_bytes_ptr = tid_curr_phys.lookup(&tid);
    u64 cur_bytes = size;
    if (cur_bytes_ptr) {
        cur_bytes += *cur_bytes_ptr;
    }
    tid_curr_phys.update(&tid, &cur_bytes);

    struct mem_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.tid = tid;
    ev.pid = pid;
    ev.type = 1; // ALLOC
    ev.size_bytes = size;
    ev.pfn = pfn;
    ev.current_total_bytes = cur_bytes;

    struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
    if (req_id_key != NULL) {
        struct resource_usage_t *usage = request_resources.lookup(req_id_key);
        if (usage != NULL) {
            if (cur_bytes > usage->peak_physical_bytes) {
                usage->peak_physical_bytes = cur_bytes;
            }
        }
        pfn_to_request_id.update(&pfn, req_id_key);
        bpf_probe_read_kernel_str(&ev.request_id, sizeof(ev.request_id), req_id_key->id);
    } else {
        ev.request_id[0] = '-';
    }

    mem_events.perf_submit(args, &ev, sizeof(ev));

    return 0;
}

TRACEPOINT_PROBE(kmem, mm_page_free) {
    struct free_args_t *ctx = (struct free_args_t *)args;
    u64 pfn = ctx->pfn;
    u32 order = ctx->order;

    u32 *owner_tid_ptr = pfn_owner.lookup(&pfn);
    if (!owner_tid_ptr) return 0;
    u32 tid = *owner_tid_ptr;

    u64 size = (1ULL << order) * 4096;
    u64 *cur_bytes_ptr = tid_curr_phys.lookup(&tid);
    u64 cur_bytes = 0;
    if (cur_bytes_ptr) {
        if (*cur_bytes_ptr >= size) cur_bytes = *cur_bytes_ptr - size;
    }
    tid_curr_phys.update(&tid, &cur_bytes);

    struct mem_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.tid = tid;
    ev.pid = 0;
    ev.type = 0; // FREE
    ev.size_bytes = size;
    ev.pfn = pfn;
    ev.current_total_bytes = cur_bytes;

    struct request_id_key_t *req_id_key = pfn_to_request_id.lookup(&pfn);
    if (req_id_key != NULL) {
        bpf_probe_read_kernel_str(&ev.request_id, sizeof(ev.request_id), req_id_key->id);
        pfn_to_request_id.delete(&pfn);
    } else {
        ev.request_id[0] = '-';
    }

    mem_events.perf_submit(args, &ev, sizeof(ev));

    pfn_owner.delete(&pfn);
    return 0;
}
