// ═══════════════════════════════════════════════════════════════
// io_tracking.c — Network & Disk I/O Syscall Tracking
//   Also detects Apache Thrift binary-framed messages on plain TCP
//   so that DeathStarBench inter-service calls are attributed.
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

    // Save recv buffer pointer for Thrift detection at exit.
    struct thrift_recv_args_t targs;
    __builtin_memset(&targs, 0, sizeof(targs));
    targs.fd  = fd;
    targs.buf = (void *)args->ubuf;
    thrift_recv_args.update(&tid, &targs);

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

            // Save recv buffer pointer for Thrift detection at exit.
            struct thrift_recv_args_t targs;
            __builtin_memset(&targs, 0, sizeof(targs));
            targs.fd  = fd;
            targs.buf = (void *)args->buf;
            thrift_recv_args.update(&tid, &targs);

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
// Shared exit handler for I/O byte accounting
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

// ═══════════════════════════════════════════════════════════════
// Thrift binary-protocol detection helper
//
// Thrift strict-binary framed wire format (TFramedTransport):
//   [4 B frame_size BE] [4 B version|type = 0x80 0x01 0x00 TT]
//   [4 B name_len BE] [name_len B method] [4 B seq_id BE] [fields]
//
// Unframed strict-binary:
//   [4 B version|type = 0x80 0x01 0x00 TT]
//   [4 B name_len BE] [name_len B method] [4 B seq_id BE] [fields]
//
// We detect the magic bytes, read THRIFT_CAPTURE_SIZE bytes, attach
// the connection 4-tuple, and emit a thrift_event to userspace.
// ═══════════════════════════════════════════════════════════════

static inline void detect_and_emit_thrift(void *ctx, long ret, u32 tid) {
    struct thrift_recv_args_t *tptr = thrift_recv_args.lookup(&tid);
    if (tptr == NULL) return;

    void *buf      = tptr->buf;
    u32  saved_fd  = tptr->fd;
    thrift_recv_args.delete(&tid);

    if (ret <= 0 || buf == NULL) return;

    // Read the first 8 bytes to check for Thrift magic.
    // Stack read of 8 bytes is always safe for the verifier.
    u8 hdr[8];
    __builtin_memset(hdr, 0, sizeof(hdr));
    if (bpf_probe_read_user(hdr, sizeof(hdr), buf) != 0) return;

    // Framed strict binary:   hdr[4..6] == 0x80 0x01 0x00
    // Unframed strict binary: hdr[0..2] == 0x80 0x01 0x00
    u8 is_thrift = 0;
    if (hdr[4] == 0x80 && hdr[5] == 0x01 && hdr[6] == 0x00) is_thrift = 1;
    if (hdr[0] == 0x80 && hdr[1] == 0x01 && hdr[2] == 0x00) is_thrift = 1;
    if (!is_thrift) return;

    // Pull scratch buffer from per-CPU array (avoids large stack alloc).
    u32 zero = 0;
    struct thrift_event_t *evt = thrift_scratch.lookup(&zero);
    if (evt == NULL) return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->tid = tid;
    evt->has_conn_info = 0;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Always read exactly THRIFT_CAPTURE_SIZE bytes (constant required by
    // the verifier); data_len tells userspace how many bytes are valid.
    u32 copy_len = (u32)ret;
    if (copy_len > THRIFT_CAPTURE_SIZE) copy_len = THRIFT_CAPTURE_SIZE;
    evt->data_len = copy_len;
    bpf_probe_read_user(evt->data, THRIFT_CAPTURE_SIZE, buf);

    // Attach connection 4-tuple from the fd→conn cache.
    struct conn_tuple_t *conn = fd_to_conn.lookup(&saved_fd);
    if (conn != NULL) {
        evt->src_ip   = conn->src_ip;
        evt->src_port = conn->src_port;
        evt->dst_ip   = conn->dst_ip;
        evt->dst_port = conn->dst_port;
        evt->has_conn_info = 1;
    }

    thrift_events.perf_submit(ctx, evt, sizeof(*evt));
}

// ═══════════════════════════════════════════════════════════════
// Exit tracepoints: byte accounting + Thrift detection
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    handle_sys_exit(args->ret, 1);
    u32 tid = (u32)bpf_get_current_pid_tgid();
    detect_and_emit_thrift(args, args->ret, tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    handle_sys_exit(args->ret, 1);
    u32 tid = (u32)bpf_get_current_pid_tgid();
    detect_and_emit_thrift(args, args->ret, tid);
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
