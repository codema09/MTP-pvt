// ═══════════════════════════════════════════════════════════════
// io_tracking.c — Network & Disk I/O Syscall Tracking
//   Also detects Apache Thrift binary-framed messages on plain TCP
//   so that DeathStarBench inter-service calls are attributed.
// ═══════════════════════════════════════════════════════════════

struct user_msghdr_local {
    void *msg_name;
    int msg_namelen;
    int __pad1;
    void *msg_iov; // struct iovec *
    unsigned long msg_iovlen;
    void *msg_control;
    unsigned long msg_controllen;
    unsigned int msg_flags;
};

struct iovec_local {
    void *iov_base;
    unsigned long iov_len;
};

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

    u64 pid_fd = (pid_tgid & 0xFFFFFFFF00000000ULL) | (u32)fd;
    fd_to_conn.update(&pid_fd, &conn);
    tid_to_fd.update(&pid_tgid, &fd);

    u64 *existing_start = tid_to_thread_start.lookup(&tid);
    if (existing_start == NULL) {
        u64 start_time = bpf_ktime_get_ns();
        tid_to_thread_start.update(&tid, &start_time);

        // The thread is on-CPU right now (executing this syscall). If
        // sched_switch PART 2 didn't write a burst-start record (because
        // neither tid_to_thread_start nor tid_to_request_id existed at the
        // last schedule-in), seed one here.  PART 1 will then save the burst
        // to tid_cpu_pre_assign instead of silently discarding it.
        struct cpu_burst_start_t *existing_burst = cpu_burst_start_map.lookup(&tid);
        if (existing_burst == NULL) {
            struct cpu_burst_start_t new_burst = {};
            new_burst.ts           = start_time;
            new_burst.cycles       = perf_cycles.perf_read(CUR_CPU_IDENTIFIER);
            new_burst.instructions = perf_instructions.perf_read(CUR_CPU_IDENTIFIER);
            cpu_burst_start_map.update(&tid, &new_burst);
        }
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

            u64 pid_fd = (pid_tgid & 0xFFFFFFFF00000000ULL) | (u32)fd;
            fd_to_conn.update(&pid_fd, &conn);
            tid_to_fd.update(&pid_tgid, &fd);

            u64 *existing_start = tid_to_thread_start.lookup(&tid);
            if (existing_start == NULL) {
                u64 start_time = bpf_ktime_get_ns();
                tid_to_thread_start.update(&tid, &start_time);

                struct cpu_burst_start_t *existing_burst = cpu_burst_start_map.lookup(&tid);
                if (existing_burst == NULL) {
                    struct cpu_burst_start_t new_burst = {};
                    new_burst.ts           = start_time;
                    new_burst.cycles       = perf_cycles.perf_read(CUR_CPU_IDENTIFIER);
                    new_burst.instructions = perf_instructions.perf_read(CUR_CPU_IDENTIFIER);
                    cpu_burst_start_map.update(&tid, &new_burst);
                }
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

// ═══════════════════════════════════════════════════════════════
// Outgoing Thrift binary-protocol detection helper
// ═══════════════════════════════════════════════════════════════

static inline void detect_and_emit_outgoing_thrift(void *ctx, struct sock *sk, int fd, const void *buf, unsigned long count, u32 tid) {
    if (count < 8 || buf == NULL) return;

    u8 hdr[8];
    __builtin_memset(hdr, 0, sizeof(hdr));
    if (bpf_probe_read_user(hdr, sizeof(hdr), buf) != 0) return;

    u8 is_thrift = 0;
    u8 msg_type = 0;
    u32 name_len = 0;
    u32 method_offset = 0;
    u32 seq_id_offset = 0;

    // Check if Unframed Strict: hdr[0..2] == 0x80 0x01 0x00
    if (hdr[0] == 0x80 && hdr[1] == 0x01 && hdr[2] == 0x00) {
        is_thrift = 1;
        msg_type = hdr[3];
        u32 *len_ptr = (u32 *)(hdr + 4);
        name_len = bpf_ntohl(*len_ptr);
        method_offset = 8;
        seq_id_offset = 8 + (name_len & 31);
    }
    // Check if Framed Strict: hdr[4..6] == 0x80 0x01 0x00
    else if (hdr[4] == 0x80 && hdr[5] == 0x01 && hdr[6] == 0x00) {
        is_thrift = 1;
        msg_type = hdr[7];
        u32 len_be = 0;
        bpf_probe_read_user(&len_be, 4, buf + 8);
        name_len = bpf_ntohl(len_be);
        method_offset = 12;
        seq_id_offset = 12 + (name_len & 31);
    }
    else {
        // Non-Strict Binary Protocol checks (Common in Python Thrift)
        u32 words[2];
        bpf_probe_read_user(words, 8, buf);
        u32 len1 = bpf_ntohl(words[0]);
        u32 len2 = bpf_ntohl(words[1]);
        
        if (len1 > 0 && len1 <= 32) {
            u8 type_byte = 0;
            if (bpf_probe_read_user(&type_byte, 1, buf + 4 + len1) == 0) {
                if (type_byte == 1 || type_byte == 4) {
                    is_thrift = 1;
                    msg_type = type_byte;
                    name_len = len1;
                    method_offset = 4;
                    seq_id_offset = 4 + (name_len & 31) + 1; // +1 for the type byte
                }
            }
        }
        
        if (!is_thrift && len2 > 0 && len2 <= 32) {
            u8 type_byte = 0;
            if (bpf_probe_read_user(&type_byte, 1, buf + 8 + len2) == 0) {
                if (type_byte == 1 || type_byte == 4) {
                    is_thrift = 1;
                    msg_type = type_byte;
                    name_len = len2;
                    method_offset = 8;
                    seq_id_offset = 8 + (name_len & 31) + 1;
                }
            }
        }
    }

    u16 dport_local = 0;
    if (sk != NULL) {
        struct inet_sock *inet_tmp = (struct inet_sock *)sk;
        u16 dport_be_tmp = 0;
        bpf_probe_read_kernel(&dport_be_tmp, sizeof(u16), &inet_tmp->inet_dport);
        dport_local = bpf_ntohs(dport_be_tmp);
    }

    u8 is_db = 0;
    if (dport_local == 11211 || dport_local == 27017 || dport_local == 6379 || dport_local == 3306) {
        is_db = 1;
    }

    if (!is_thrift && !is_db) return;
    if (!is_db && msg_type != 1 && msg_type != 4) return;

    u32 zero = 0;
    struct thrift_out_event_t *evt = thrift_out_scratch.lookup(&zero);
    if (!evt) return;
    __builtin_memset(evt, 0, sizeof(*evt));

    evt->tid = tid;

    if (sk != NULL) {
        struct inet_sock *inet = (struct inet_sock *)sk;
        u16 sport_be = 0, dport_be = 0;
        bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_saddr);
        bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_daddr);
        bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
        bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
        evt->src_port = bpf_ntohs(sport_be);
        evt->dst_port = bpf_ntohs(dport_be);
    }

    struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
    if (req_id_key != NULL) {
        #pragma unroll
        for (int i = 0; i < MAX_REQUEST_ID_LEN; i++) {
            evt->parent_request_id[i] = req_id_key->id[i];
        }
        evt->has_request_id = 1;
    } else {
        evt->has_request_id = 0;
    }

    if (is_db && !is_thrift) {
        evt->method[0] = 'D'; evt->method[1] = 'B'; evt->method[2] = '_'; evt->method[3] = 'O'; evt->method[4] = 'P'; evt->method[5] = '\0';
        evt->seq_id = 0;
        evt->payload_req_id = 0;
        thrift_out_events.perf_submit(ctx, evt, sizeof(*evt));
        return;
    }

    if (name_len > 0 && name_len <= 32) {
        u32 safe_name_len = name_len & 31;
        bpf_probe_read_user(evt->method, sizeof(evt->method), buf + method_offset);
        u32 seq_id_be = 0;
        if (bpf_probe_read_user(&seq_id_be, 4, buf + seq_id_offset) == 0) {
            evt->seq_id = bpf_ntohl(seq_id_be);
            
            u32 field_meta_offset = seq_id_offset + 4;
            u8 field_type = 0;
            evt->payload_req_id = 0;
            if (bpf_probe_read_user(&field_type, 1, buf + field_meta_offset) == 0 && field_type == 0x0A) {
                u16 field_id = 0;
                if (bpf_probe_read_user(&field_id, 2, buf + field_meta_offset + 1) == 0 && bpf_ntohs(field_id) == 1) {
                    u64 val_be = 0;
                    if (bpf_probe_read_user(&val_be, 8, buf + field_meta_offset + 3) == 0) {
                        evt->payload_req_id = (u64)__builtin_bswap64(val_be);
                    }
                }
            }

            thrift_out_events.perf_submit(ctx, evt, sizeof(*evt));
        }
    }
}



TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    if (!is_target_process()) return 0;
    u64 t0 = bpf_ktime_get_ns();
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;

    struct sock *sk = get_sock_from_fd(fd);
    if (sk == NULL) return 0;
    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;

    u8 type = 2;
    active_sock_op.update(&tid, &type);
    detect_and_emit_outgoing_thrift(args, sk, fd, (const void *)args->buff, (size_t)args->len, tid);

    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&tid, &v); }
    else { tid_to_overhead_ns.update(&tid, &delta); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    if (!is_target_process()) return 0;
    u64 t0 = bpf_ktime_get_ns();
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;

    struct sock *sk = get_sock_from_fd(fd);
    if (sk != NULL) {
        u16 family;
        bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
        if (family == AF_INET) {
            u8 type = 2;
            active_sock_op.update(&tid, &type);
            detect_and_emit_outgoing_thrift(args, sk, fd, (const void *)args->buf, (size_t)args->count, tid);
            u64 t1 = bpf_ktime_get_ns();
            u64 delta = t1 - t0;
            u64 *acc = tid_to_overhead_ns.lookup(&tid);
            if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&tid, &v); }
            else { tid_to_overhead_ns.update(&tid, &delta); }
            return 0;
        }
    }
    if (fd > 2) {
        u8 type = 4;
        active_sock_op.update(&tid, &type);
    }
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&tid, &v); }
    else { tid_to_overhead_ns.update(&tid, &delta); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_writev) {
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
            
            struct inet_sock *inet = (struct inet_sock *)sk;
            u16 dport_be = 0;
            bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
            u16 dport_local = bpf_ntohs(dport_be);

            if (dport_local == 11211 || dport_local == 27017 || dport_local == 6379 || dport_local == 3306) {
                u32 zero = 0;
                struct thrift_out_event_t *evt = thrift_out_scratch.lookup(&zero);
                if (evt) {
                    __builtin_memset(evt, 0, sizeof(*evt));
                    evt->tid = tid;
                    u16 sport_be = 0;
                    bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_saddr);
                    bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_daddr);
                    bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
                    evt->src_port = bpf_ntohs(sport_be);
                    evt->dst_port = bpf_ntohs(dport_be);

                    struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
                    if (req_id_key) {
                        #pragma unroll
                        for (int i = 0; i < MAX_REQUEST_ID_LEN; i++) {
                            evt->parent_request_id[i] = req_id_key->id[i];
                        }
                        evt->has_request_id = 1;
                    } else {
                        evt->has_request_id = 0;
                    }

                    evt->method[0] = 'D'; evt->method[1] = 'B'; evt->method[2] = '_'; evt->method[3] = 'O'; evt->method[4] = 'P'; evt->method[5] = '\0';
                    evt->seq_id = 0;
                    evt->payload_req_id = 0;
                    thrift_out_events.perf_submit(args, evt, sizeof(*evt));
                }
                return 0; // DB captured, don't check for Thrift
            }

            struct iovec_local iov[2];
            unsigned long count2 = args->vlen;
            if (count2 > 2) count2 = 2; // only read up to 2 iovecs
            
            if (bpf_probe_read_user(&iov, sizeof(struct iovec_local) * count2, (void *)args->vec) == 0) {
                if (iov[0].iov_len >= 8) {
                    detect_and_emit_outgoing_thrift(args, sk, fd, iov[0].iov_base, iov[0].iov_len, tid);
                } else if (count2 == 2 && iov[1].iov_len >= 8) {
                    // if first iovec is small (e.g. 4-byte frame size), check second iovec!
                    detect_and_emit_outgoing_thrift(args, sk, fd, iov[1].iov_base, iov[1].iov_len, tid);
                }
            }
            return 0;
        }
    }
    if (fd > 2) {
        u8 type = 4;
        active_sock_op.update(&tid, &type);
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
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

    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 dport_be = 0;
    bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
    u16 dport_local = bpf_ntohs(dport_be);

    if (dport_local == 11211 || dport_local == 27017 || dport_local == 6379 || dport_local == 3306) {
        u32 zero = 0;
        struct thrift_out_event_t *evt = thrift_out_scratch.lookup(&zero);
        if (evt) {
            __builtin_memset(evt, 0, sizeof(*evt));
            evt->tid = tid;
            u16 sport_be = 0;
            bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_saddr);
            bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_daddr);
            bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
            evt->src_port = bpf_ntohs(sport_be);
            evt->dst_port = bpf_ntohs(dport_be);

            struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
            if (req_id_key) {
                #pragma unroll
                for (int i = 0; i < MAX_REQUEST_ID_LEN; i++) {
                    evt->parent_request_id[i] = req_id_key->id[i];
                }
                evt->has_request_id = 1;
            } else {
                evt->has_request_id = 0;
            }

            evt->method[0] = 'D'; evt->method[1] = 'B'; evt->method[2] = '_'; evt->method[3] = 'O'; evt->method[4] = 'P'; evt->method[5] = '\0';
            evt->seq_id = 0;
            evt->payload_req_id = 0;
            thrift_out_events.perf_submit(args, evt, sizeof(*evt));
        }
        return 0; // DB captured, don't check for Thrift
    }

    struct user_msghdr_local msg;
    if (bpf_probe_read_user(&msg, sizeof(msg), (void *)args->msg) == 0) {
        struct iovec_local iov[2];
        unsigned long count2 = msg.msg_iovlen;
        if (count2 > 2) count2 = 2;
        if (count2 > 0 && bpf_probe_read_user(&iov, sizeof(struct iovec_local) * count2, (void *)msg.msg_iov) == 0) {
            if (iov[0].iov_len >= 8) {
                detect_and_emit_outgoing_thrift(args, sk, fd, iov[0].iov_base, iov[0].iov_len, tid);
            } else if (count2 == 2 && iov[1].iov_len >= 8) {
                detect_and_emit_outgoing_thrift(args, sk, fd, iov[1].iov_base, iov[1].iov_len, tid);
            }
        }
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendmmsg) {
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

    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 dport_be = 0;
    bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
    u16 dport_local = bpf_ntohs(dport_be);

    if (dport_local == 11211 || dport_local == 27017 || dport_local == 6379 || dport_local == 3306) {
        u32 zero = 0;
        struct thrift_out_event_t *evt = thrift_out_scratch.lookup(&zero);
        if (evt) {
            __builtin_memset(evt, 0, sizeof(*evt));
            evt->tid = tid;
            u16 sport_be = 0;
            bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_saddr);
            bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_daddr);
            bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
            evt->src_port = bpf_ntohs(sport_be);
            evt->dst_port = bpf_ntohs(dport_be);

            struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
            if (req_id_key) {
                #pragma unroll
                for (int i = 0; i < MAX_REQUEST_ID_LEN; i++) {
                    evt->parent_request_id[i] = req_id_key->id[i];
                }
                evt->has_request_id = 1;
            } else {
                evt->has_request_id = 0;
            }

            evt->method[0] = 'D'; evt->method[1] = 'B'; evt->method[2] = '_'; evt->method[3] = 'O'; evt->method[4] = 'P'; evt->method[5] = '\0';
            evt->seq_id = 0;
            evt->payload_req_id = 0;
            thrift_out_events.perf_submit(args, evt, sizeof(*evt));
        }
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
                    if (*type == 1) {
                         res->bytes_recv += ret;
                         if (res->first_recv_ns == 0) res->first_recv_ns = bpf_ktime_get_ns();
                    }
                    else if (*type == 2) {
                         res->bytes_sent += ret;
                         res->last_send_ns = bpf_ktime_get_ns();
                    }
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
    u32 off = 0;
    if (hdr[4] == 0x80 && hdr[5] == 0x01 && hdr[6] == 0x00) { is_thrift = 1; off = 4; }
    if (hdr[0] == 0x80 && hdr[1] == 0x01 && hdr[2] == 0x00) { is_thrift = 1; off = 0; }
    if (!is_thrift) return;

    // Pull scratch buffer from per-CPU array (avoids large stack alloc).
    u32 zero = 0;
    struct thrift_event_t *evt = thrift_scratch.lookup(&zero);
    if (evt == NULL) return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->pid = pid_tgid >> 32;
    evt->tid = tid;
    evt->has_conn_info = 0;
    evt->has_request_id = 0;
    __builtin_memset(evt->request_id, 0, sizeof(evt->request_id));
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Always read exactly THRIFT_CAPTURE_SIZE bytes (constant required by
    // the verifier); data_len tells userspace how many bytes are valid.
    u32 copy_len = (u32)ret;
    if (copy_len > THRIFT_CAPTURE_SIZE) copy_len = THRIFT_CAPTURE_SIZE;
    evt->data_len = copy_len;
    bpf_probe_read_user(evt->data, THRIFT_CAPTURE_SIZE, buf);

    // Attach connection 4-tuple from the fd→conn cache.
    u64 pid_fd = (pid_tgid & 0xFFFFFFFF00000000ULL) | saved_fd;
    struct conn_tuple_t *conn = fd_to_conn.lookup(&pid_fd);
    if (conn != NULL) {
        evt->src_ip   = conn->src_ip;
        evt->src_port = conn->src_port;
        evt->dst_ip   = conn->dst_ip;
        evt->dst_port = conn->dst_port;
        evt->has_conn_info = 1;
    }

    u8 msg_type = 0;
    if (bpf_probe_read_user(&msg_type, 1, buf + off + 3) == 0) {
        if (msg_type == 1 || msg_type == 4) {
            u32 name_len_be = 0;
            if (bpf_probe_read_user(&name_len_be, 4, buf + off + 4) == 0) {
                u32 name_len = bpf_ntohl(name_len_be);
                if (name_len > 0 && name_len <= 32) {
                    char method[32];
                    __builtin_memset(method, 0, sizeof(method));
                    if (bpf_probe_read_user(method, sizeof(method), buf + off + 8) == 0) {
                        u32 seq_id_be = 0;
                        u32 safe_name_len = name_len & 31;
                        if (bpf_probe_read_user(&seq_id_be, 4, buf + off + 8 + safe_name_len) == 0) {
                            u32 seq_id = bpf_ntohl(seq_id_be);
                            
                            u32 field_meta_offset = off + 8 + safe_name_len + 4;
                            u8 field_type = 0;
                            evt->payload_req_id = 0;
                            if (bpf_probe_read_user(&field_type, 1, buf + field_meta_offset) == 0 && field_type == 0x0A) {
                                u16 field_id = 0;
                                if (bpf_probe_read_user(&field_id, 2, buf + field_meta_offset + 1) == 0 && bpf_ntohs(field_id) == 1) {
                                    u64 val_be = 0;
                                    if (bpf_probe_read_user(&val_be, 8, buf + field_meta_offset + 3) == 0) {
                                        evt->payload_req_id = (u64)__builtin_bswap64(val_be);
                                    }
                                }
                            }
                            
                            u64 ts = bpf_ktime_get_ns();
                            u64 hash = ((u64)evt->src_ip) ^ ((u64)evt->src_port << 32) ^ ts;
                            hash ^= hash >> 33;
                            hash *= 0xff51afd7ed558ccdULL;
                            hash ^= hash >> 33;
                            hash *= 0xc4ceb9fe1a85ec53ULL;
                            hash ^= hash >> 33;
                            
                            char hex[17];
                            __builtin_memset(hex, 0, sizeof(hex));
                            #pragma unroll
                            for (int i = 0; i < 16; i++) {
                                u8 nibble = (hash >> (i * 4)) & 0xF;
                                hex[15 - i] = nibble < 10 ? '0' + nibble : 'a' + (nibble - 10);
                            }
                            
                            char seq_str[10];
                            int seq_len = 0;
                            u32 val = seq_id;
                            if (val == 0) {
                                seq_str[0] = '0';
                                seq_len = 1;
                            } else {
                                #pragma unroll
                                for (int i = 0; i < 10; i++) {
                                    if (val > 0) {
                                        seq_str[i] = '0' + (val % 10);
                                        val /= 10;
                                        seq_len++;
                                    }
                                }
                            }
                            
                            struct request_id_key_t *req_id_key = req_id_key_scratch.lookup(&zero);
                            if (!req_id_key) return;
                            __builtin_memset(req_id_key, 0, sizeof(*req_id_key));

                            int pos = 0;
                            #pragma unroll
                            for (int i = 0; i < 32; i++) {
                                if (i < safe_name_len && pos < sizeof(req_id_key->id) - 1) {
                                    req_id_key->id[pos++] = method[i];
                                }
                            }
                            if (pos < sizeof(req_id_key->id) - 1) req_id_key->id[pos++] = '_';
                            if (pos < sizeof(req_id_key->id) - 1) req_id_key->id[pos++] = 's';
                            if (pos < sizeof(req_id_key->id) - 1) req_id_key->id[pos++] = 'e';
                            if (pos < sizeof(req_id_key->id) - 1) req_id_key->id[pos++] = 'q';
                            
                            #pragma unroll
                            for (int i = 9; i >= 0; i--) {
                                if (i < seq_len && pos < sizeof(req_id_key->id) - 1) {
                                    req_id_key->id[pos++] = seq_str[i];
                                }
                            }
                            
                            if (pos < sizeof(req_id_key->id) - 1) req_id_key->id[pos++] = '_';
                            
                            #pragma unroll
                            for (int i = 0; i < 16; i++) {
                                if (pos < sizeof(req_id_key->id) - 1) {
                                    req_id_key->id[pos++] = hex[i];
                                }
                            }
                            
                            struct resource_usage_t *usage = resource_usage_scratch.lookup(&zero);
                            if (!usage) return;
                            __builtin_memset(usage, 0, sizeof(*usage));

                            #pragma unroll
                            for (int i = 0; i < MAX_REQUEST_ID_LEN; i++) {
                                usage->request_id[i] = req_id_key->id[i];
                                evt->request_id[i] = req_id_key->id[i];
                            }
                            evt->has_request_id = 1;
                            
                            usage->tid = tid;
                            usage->pid = pid_tgid >> 32;
                            usage->start_time_ns = ts;
                            usage->payload_req_id = evt->payload_req_id;
                            usage->cpu_cycles_start = ts;
                            usage->first_recv_ns = ts;
                            
                            u64 *mmap_ptr = tid_mmap_bytes.lookup(&tid);
                            if (mmap_ptr) usage->mmap_bytes = *mmap_ptr;
                            
                            u64 *mprot_ptr = tid_mprotect_bytes.lookup(&tid);
                            if (mprot_ptr) usage->mprotect_bytes = *mprot_ptr;
                            
                            u64 *phys_ptr = tid_curr_phys.lookup(&tid);
                            if (phys_ptr) usage->peak_physical_bytes = *phys_ptr;
                            
                            usage->src_ip = evt->src_ip;
                            usage->src_port = evt->src_port;
                            usage->dst_ip = evt->dst_ip;
                            usage->dst_port = evt->dst_port;
                            
                            struct pre_assign_cpu_t *pre = tid_cpu_pre_assign.lookup(&tid);
                            if (pre) {
                                usage->cpu_burst_total_ns = pre->total_ns;
                                usage->cpu_burst_count = pre->burst_count;
                                usage->cpu_cycles_total = pre->cycles;
                                usage->cpu_instructions_total = pre->instructions;
                                // Don't copy first/last_cpu_burst_ns from pre: those timestamps
                                // predate the request (thread-pool idle bursts). We delete pre
                                // below so sched_switch will start fresh timestamps for this request.
                                tid_cpu_pre_assign.delete(&tid);
                            }
                            // Leave first_cpu_burst_ns = 0 and last_cpu_burst_ns = 0.
                            // The next sched_switch that switches this thread out will record
                            // start_data->ts (start of the current burst, which covers the recv
                            // processing) as first_cpu_burst_ns — that is the correct anchor.
                            
                            request_resources.update(req_id_key, usage);
                            tid_to_request_id.update(&tid, req_id_key);
                        }
                    }
                }
            }
        }
    }

    thrift_events.perf_submit(ctx, evt, sizeof(*evt));
}

// ═══════════════════════════════════════════════════════════════
// Exit tracepoints: byte accounting + Thrift detection
// ═══════════════════════════════════════════════════════════════

// Seed cpu_burst_start_map for target threads returning from a blocking recv/read.
// This catches threads that were already blocked in recvfrom when eBPF attached
// (sys_enter never fired for them, so they were never seeded via the enter path).
static inline void seed_burst_at_exit(u32 exit_tgid, u32 exit_tid) {
    if (target_pids.lookup(&exit_tgid) == NULL) return;
    struct cpu_burst_start_t *existing = cpu_burst_start_map.lookup(&exit_tid);
    if (existing == NULL) {
        struct cpu_burst_start_t nb = {};
        nb.ts           = bpf_ktime_get_ns();
        nb.cycles       = perf_cycles.perf_read(CUR_CPU_IDENTIFIER);
        nb.instructions = perf_instructions.perf_read(CUR_CPU_IDENTIFIER);
        cpu_burst_start_map.update(&exit_tid, &nb);
    }
    // Also register TID→TGID so PART 2 can track this thread at future schedule-ins.
    tid_to_tgid.update(&exit_tid, &exit_tgid);
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    u64 t0 = bpf_ktime_get_ns();
    handle_sys_exit(args->ret, 1);
    u64 exit_pid_tgid = bpf_get_current_pid_tgid();
    u32 exit_tid  = (u32)exit_pid_tgid;
    u32 exit_tgid = exit_pid_tgid >> 32;
    detect_and_emit_thrift(args, args->ret, exit_tid);
    if (args->ret > 0) seed_burst_at_exit(exit_tgid, exit_tid);
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&exit_tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&exit_tid, &v); }
    else { tid_to_overhead_ns.update(&exit_tid, &delta); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 t0 = bpf_ktime_get_ns();
    handle_sys_exit(args->ret, 1);
    u64 exit_pid_tgid = bpf_get_current_pid_tgid();
    u32 exit_tid  = (u32)exit_pid_tgid;
    u32 exit_tgid = exit_pid_tgid >> 32;
    detect_and_emit_thrift(args, args->ret, exit_tid);
    if (args->ret > 0) seed_burst_at_exit(exit_tgid, exit_tid);
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&exit_tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&exit_tid, &v); }
    else { tid_to_overhead_ns.update(&exit_tid, &delta); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
    u64 t0 = bpf_ktime_get_ns();
    handle_sys_exit(args->ret, 0);
    u32 exit_tid = (u32)bpf_get_current_pid_tgid();
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&exit_tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&exit_tid, &v); }
    else { tid_to_overhead_ns.update(&exit_tid, &delta); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    u64 t0 = bpf_ktime_get_ns();
    handle_sys_exit(args->ret, 0);
    u32 exit_tid = (u32)bpf_get_current_pid_tgid();
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&exit_tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&exit_tid, &v); }
    else { tid_to_overhead_ns.update(&exit_tid, &delta); }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// Vector & Message Send Exits (Fixing Lost Bytes) 
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(syscalls, sys_exit_writev) {
    u64 t0 = bpf_ktime_get_ns();
    handle_sys_exit(args->ret, 0);
    u32 exit_tid = (u32)bpf_get_current_pid_tgid();
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&exit_tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&exit_tid, &v); }
    else { tid_to_overhead_ns.update(&exit_tid, &delta); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_sendmsg) {
    u64 t0 = bpf_ktime_get_ns();
    handle_sys_exit(args->ret, 0);
    u32 exit_tid = (u32)bpf_get_current_pid_tgid();
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&exit_tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&exit_tid, &v); }
    else { tid_to_overhead_ns.update(&exit_tid, &delta); }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// Vector Receive Traces (readv, recvmsg)
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(syscalls, sys_enter_readv) {
    if (!is_target_process()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 fd = (u32)args->fd;
    u64 t0 = bpf_ktime_get_ns();

    struct sock *sk = get_sock_from_fd(fd);
    void *buf_to_save = NULL;

    struct iovec_local iov[1];
    if (args->vlen > 0) {
        if (bpf_probe_read_user(&iov, sizeof(struct iovec_local), (void *)args->vec) == 0) {
            buf_to_save = iov[0].iov_base;
        }
    }

    if (sk != NULL) {
        u16 family;
        bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
        if (family == AF_INET) {
            u8 type = 1;
            active_sock_op.update(&tid, &type);
        }
    } else if (fd > 2) {
        u8 type = 3;
        active_sock_op.update(&tid, &type);
    }

    if (buf_to_save) {
        struct thrift_recv_args_t targs;
        __builtin_memset(&targs, 0, sizeof(targs));
        targs.fd  = fd;
        targs.buf = buf_to_save;
        thrift_recv_args.update(&tid, &targs);
    }

    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid);
    if (acc_ptr) { u64 acc = *acc_ptr + delta; tid_to_overhead_ns.update(&tid, &acc); }
    else { tid_to_overhead_ns.update(&tid, &delta); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_readv) {
    u64 t0 = bpf_ktime_get_ns();
    handle_sys_exit(args->ret, 1);
    u64 exit_pid_tgid = bpf_get_current_pid_tgid();
    u32 exit_tid  = (u32)exit_pid_tgid;
    u32 exit_tgid = exit_pid_tgid >> 32;
    detect_and_emit_thrift(args, args->ret, exit_tid);
    if (args->ret > 0) seed_burst_at_exit(exit_tgid, exit_tid);
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&exit_tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&exit_tid, &v); }
    else { tid_to_overhead_ns.update(&exit_tid, &delta); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvmsg) {
    if (!is_target_process()) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 fd = (u32)args->fd;
    u64 t0 = bpf_ktime_get_ns();

    struct sock *sk = get_sock_from_fd(fd);
    void *buf_to_save = NULL;

    struct user_msghdr_local msg;
    if (bpf_probe_read_user(&msg, sizeof(msg), (void *)args->msg) == 0) {
        struct iovec_local iov[1];
        if (msg.msg_iovlen > 0) {
            if (bpf_probe_read_user(&iov, sizeof(struct iovec_local), (void *)msg.msg_iov) == 0) {
                buf_to_save = iov[0].iov_base;
            }
        }
    }

    if (sk != NULL) {
        u16 family;
        bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
        if (family == AF_INET) {
            u8 type = 1;
            active_sock_op.update(&tid, &type);
        }
    }

    if (buf_to_save) {
        struct thrift_recv_args_t targs;
        __builtin_memset(&targs, 0, sizeof(targs));
        targs.fd  = fd;
        targs.buf = buf_to_save;
        thrift_recv_args.update(&tid, &targs);
    }

    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid);
    if (acc_ptr) { u64 acc = *acc_ptr + delta; tid_to_overhead_ns.update(&tid, &acc); }
    else { tid_to_overhead_ns.update(&tid, &delta); }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_recvmsg) {
    u64 t0 = bpf_ktime_get_ns();
    handle_sys_exit(args->ret, 1);
    u64 exit_pid_tgid = bpf_get_current_pid_tgid();
    u32 exit_tid  = (u32)exit_pid_tgid;
    u32 exit_tgid = exit_pid_tgid >> 32;
    detect_and_emit_thrift(args, args->ret, exit_tid);
    if (args->ret > 0) seed_burst_at_exit(exit_tgid, exit_tid);
    u64 t1 = bpf_ktime_get_ns();
    u64 delta = t1 - t0;
    u64 *acc = tid_to_overhead_ns.lookup(&exit_tid);
    if (acc) { u64 v = *acc + delta; tid_to_overhead_ns.update(&exit_tid, &v); }
    else { tid_to_overhead_ns.update(&exit_tid, &delta); }
    return 0;
}
