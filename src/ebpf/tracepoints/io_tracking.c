// ═══════════════════════════════════════════════════════════════
// io_tracking.c — Network & Disk I/O Syscall Tracking
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    if (!is_target_process()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 fd = (u32)args->fd;
    u64 t0 = bpf_ktime_get_ns();

    struct sock *sk = get_sock_from_fd(fd);
    if (sk == NULL) return 0;

    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    u8 type = 1;
    active_sock_op.update(&tid, &type);

    struct conn_tuple_t conn = {};
    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 sport_be = 0, dport_be = 0;
    bpf_probe_read_kernel(&conn.src_ip, sizeof(u32), &inet->inet_daddr);
    bpf_probe_read_kernel(&conn.dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
    bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
    bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
    conn.src_port = bpf_ntohs(dport_be);
    conn.dst_port = bpf_ntohs(sport_be);

    fd_to_conn.update(&fd, &conn);
    tid_to_fd.update(&pid_tgid, &fd);

    u64 *existing_start = tid_to_thread_start.lookup(&tid);
    if (existing_start == NULL) {
        u64 start_time = bpf_ktime_get_ns();
        tid_to_thread_start.update(&tid, &start_time);
    }

    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid);
    if (acc_ptr) {
        u64 acc = *acc_ptr + delta;
        tid_to_overhead_ns.update(&tid, &acc);
    } else {
        tid_to_overhead_ns.update(&tid, &delta);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    if (!is_target_process()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 fd = (u32)args->fd;
    u64 t0 = bpf_ktime_get_ns();

    struct sock *sk = get_sock_from_fd(fd);
    if (sk != NULL) {
        u16 family;
        bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
        if (family == AF_INET) {
            u8 type = 1;
            active_sock_op.update(&tid, &type);

            struct conn_tuple_t conn = {};
            struct inet_sock *inet = (struct inet_sock *)sk;
            u16 sport_be = 0, dport_be = 0;
            bpf_probe_read_kernel(&conn.src_ip, sizeof(u32), &inet->inet_daddr);
            bpf_probe_read_kernel(&conn.dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
            bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
            bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
            conn.src_port = bpf_ntohs(dport_be);
            conn.dst_port = bpf_ntohs(sport_be);

            fd_to_conn.update(&fd, &conn);
            tid_to_fd.update(&pid_tgid, &fd);

            u64 *existing_start = tid_to_thread_start.lookup(&tid);
            if (existing_start == NULL) {
                u64 start_time = bpf_ktime_get_ns();
                tid_to_thread_start.update(&tid, &start_time);
            }

            u64 t1 = bpf_ktime_get_ns();
            u64 delta = t1 - t0;
            u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid);
            if (acc_ptr) {
                u64 acc = *acc_ptr + delta;
                tid_to_overhead_ns.update(&tid, &acc);
            } else {
                tid_to_overhead_ns.update(&tid, &delta);
            }
            return 0;
        }
    }
    if (fd > 2) {
        u8 type = 3;
        active_sock_op.update(&tid, &type);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    if (!is_target_process()) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;

    struct sock *sk = get_sock_from_fd(fd);
    if (sk == NULL) return 0;
    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    u8 type = 2;
    active_sock_op.update(&tid, &type);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    if (!is_target_process()) return 0;
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;

    struct sock *sk = get_sock_from_fd(fd);
    if (sk != NULL) {
        u16 family;
        bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
        if (family == AF_INET) {
            u8 type = 2;
            active_sock_op.update(&tid, &type);
            return 0;
        }
    }
    if (fd > 2) {
        u8 type = 4;
        active_sock_op.update(&tid, &type);
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// Shared exit handler for all I/O syscalls
// ═══════════════════════════════════════════════════════════════

static inline void handle_sys_exit(long ret, int is_recv) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u8 *type = active_sock_op.lookup(&tid);

    if (type) {
        if (ret > 0) {
            struct request_id_key_t *req_id = tid_to_request_id.lookup(&tid);
            if (req_id) {
                struct resource_usage_t *res = request_resources.lookup(req_id);
                if (res) {
                    if (*type == 1) res->bytes_recv += ret;
                    else if (*type == 2) res->bytes_sent += ret;
                    else if (*type == 3) res->disk_read_bytes += ret;
                    else if (*type == 4) res->disk_write_bytes += ret;
                }
            }
        }
        active_sock_op.delete(&tid);
    }
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    handle_sys_exit(args->ret, 1);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    handle_sys_exit(args->ret, 1);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
    handle_sys_exit(args->ret, 0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    handle_sys_exit(args->ret, 0);
    return 0;
}
