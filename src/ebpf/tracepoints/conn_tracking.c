// ═══════════════════════════════════════════════════════════════
// conn_tracking.c — Outgoing TCP Connection Tracking
// ═══════════════════════════════════════════════════════════════
//
// Hooks sys_enter_connect (saves fd + destination from sockaddr) and
// sys_exit_connect (reads source IP/port from the now-connected socket,
// then emits a conn_event_t so userspace can print the 4-tuple).

#include <linux/in.h>

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (!is_target_process()) return 0;

    // Read address family from userspace sockaddr
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), (void *)args->uservaddr);
    if (family != AF_INET) return 0;

    // Read the full sockaddr_in in one shot
    struct sockaddr_in sin = {};
    bpf_probe_read_user(&sin, sizeof(sin), (void *)args->uservaddr);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct tcp_connect_args_t cargs = {};
    cargs.fd      = (u32)args->fd;
    cargs.dst_ip  = sin.sin_addr.s_addr;          // already in network byte order
    cargs.dst_port = bpf_ntohs(sin.sin_port);     // convert to host byte order for display

    tcp_connect_args.update(&pid_tgid, &cargs);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid       = (u32)pid_tgid;

    struct tcp_connect_args_t *cargs = tcp_connect_args.lookup(&pid_tgid);
    if (!cargs) return 0;

    // Accept ret==0 (connected) or ret==-115 (EINPROGRESS, non-blocking)
    long ret = args->ret;
    if (ret != 0 && ret != -115) {
        tcp_connect_args.delete(&pid_tgid);
        return 0;
    }

    // Read source IP / port from the now-connected socket
    u32 src_ip  = 0;
    u16 src_port = 0;
    struct sock *sk = get_sock_from_fd(cargs->fd);
    if (sk != NULL) {
        struct inet_sock *inet = (struct inet_sock *)sk;
        u16 sport_be = 0;
        bpf_probe_read_kernel(&src_ip,   sizeof(u32), &inet->inet_saddr);
        bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
        src_port = bpf_ntohs(sport_be);
    }

    struct conn_event_t ev = {};
    ev.tid      = tid;
    ev.src_ip   = src_ip;
    ev.src_port = src_port;
    ev.dst_ip   = cargs->dst_ip;
    ev.dst_port = cargs->dst_port;

    conn_events.perf_submit(args, &ev, sizeof(ev));
    tcp_connect_args.delete(&pid_tgid);
    return 0;
}
