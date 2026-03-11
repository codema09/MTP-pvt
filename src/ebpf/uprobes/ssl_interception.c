// ═══════════════════════════════════════════════════════════════
// ssl_interception.c — SSL/TLS Read Interception (uprobes)
// ═══════════════════════════════════════════════════════════════

int probe_ssl_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    if (!is_target_process()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ssl_read_args.update(&pid_tgid, &buf);
    return 0;
}

int probe_ssl_read_exit(struct pt_regs *ctx) {
    u64 t0 = bpf_ktime_get_ns();
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    void **buf_ptr = ssl_read_args.lookup(&pid_tgid);
    if (buf_ptr == NULL) return 0;
    void *buf = *buf_ptr;
    ssl_read_args.delete(&pid_tgid);

    u32 zero = 0;
    struct ssl_data_event_t *evt = event_scratch.lookup(&zero);
    if (evt == NULL) return 0;

    evt->pid = pid;
    evt->tid = tid;
    evt->has_conn_info = 0;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    u32 copy_len = (u32)ret;
    if (copy_len > MAX_HEADER_SIZE) copy_len = MAX_HEADER_SIZE;
    bpf_probe_read_user(&evt->data, copy_len, buf);
    evt->data_len = copy_len;

    u32 *fd_ptr = tid_to_fd.lookup(&pid_tgid);
    if (fd_ptr != NULL) {
        u32 fd = *fd_ptr;
        struct sock *sk = get_sock_from_fd(fd);
        if (sk != NULL) {
            u16 family;
            bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
            if (family == AF_INET) {
                struct inet_sock *inet = (struct inet_sock *)sk;
                u16 sport_be = 0, dport_be = 0;
                bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_daddr);
                bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
                bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
                bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
                evt->src_port = bpf_ntohs(dport_be);
                evt->dst_port = bpf_ntohs(sport_be);
                evt->has_conn_info = 1;
            }
        }
    }

    ssl_events.perf_submit(ctx, evt, sizeof(*evt));

    u32 tid_acc = (u32)pid_tgid;
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
    if (acc_ptr) {
        u64 acc = *acc_ptr + delta;
        tid_to_overhead_ns.update(&tid_acc, &acc);
    } else {
        tid_to_overhead_ns.update(&tid_acc, &delta);
    }
    return 0;
}

int probe_ssl_read_ex_enter(struct pt_regs *ctx, void *ssl, void *buf,
                             unsigned long num, void *readbytes) {
    if (!is_target_process()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_read_ex_args_t args = {.buf = buf, .readbytes_ptr = readbytes};
    ssl_read_ex_args.update(&pid_tgid, &args);
    return 0;
}

int probe_ssl_read_ex_exit(struct pt_regs *ctx) {
    u64 t0 = bpf_ktime_get_ns();
    int ret = PT_REGS_RC(ctx);
    if (ret != 1) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;

    struct ssl_read_ex_args_t *args = ssl_read_ex_args.lookup(&pid_tgid);
    if (args == NULL) return 0;

    unsigned long bytes_read = 0;
    bpf_probe_read_user(&bytes_read, sizeof(bytes_read), args->readbytes_ptr);
    if (bytes_read <= 0) {
        ssl_read_ex_args.delete(&pid_tgid);
        return 0;
    }

    void *buf = args->buf;
    u32 zero = 0;
    struct ssl_data_event_t *evt = event_scratch.lookup(&zero);
    if (evt == NULL) {
        ssl_read_ex_args.delete(&pid_tgid);
        return 0;
    }

    evt->pid = pid;
    evt->tid = tid;
    evt->has_conn_info = 0;

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    u32 copy_len = (u32)bytes_read;
    if (copy_len > MAX_HEADER_SIZE) copy_len = MAX_HEADER_SIZE;
    bpf_probe_read_user(&evt->data, copy_len, buf);
    evt->data_len = copy_len;

    ssl_read_ex_args.delete(&pid_tgid);

    u32 *fd_ptr = tid_to_fd.lookup(&pid_tgid);
    if (fd_ptr != NULL) {
        u32 fd = *fd_ptr;
        struct sock *sk = get_sock_from_fd(fd);
        if (sk != NULL) {
            u16 family;
            bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
            if (family == AF_INET) {
                struct inet_sock *inet = (struct inet_sock *)sk;
                u16 sport_be = 0, dport_be = 0;
                bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_daddr);
                bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
                bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
                bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
                evt->src_port = bpf_ntohs(dport_be);
                evt->dst_port = bpf_ntohs(sport_be);
                evt->has_conn_info = 1;
            }
        }
    }

    ssl_events.perf_submit(ctx, evt, sizeof(*evt));

    u32 tid_acc = (u32)pid_tgid;
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
    if (acc_ptr) {
        u64 acc = *acc_ptr + delta;
        tid_to_overhead_ns.update(&tid_acc, &acc);
    } else {
        tid_to_overhead_ns.update(&tid_acc, &delta);
    }
    return 0;
}
