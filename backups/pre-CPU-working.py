#!/usr/bin/env python3
"""
Integrated HTTPS Server Sniffer & Resource Profiler (FINAL FIXED + IO + Disk)
=============================================================================
- Fixed BPF Verifier Error (ssl_read_ex_args map type).
- Restored "fancy tables" and User History.
- Added Global Summary on Exit.
- Tracks Peak Physical Memory & Virtual Memory per request.
- Fixed: Tracks Send/Recv bytes via syscall hooking (Verifier Fix).
- Tracks Disk Read/Write KB on non-socket file descriptors.

Usage: sudo python3 integrated_sniffer_full.py -p <PID>
"""

from bcc import BPF
import socket
import struct
import ctypes
import time
import re
import os
import sys
import argparse
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

LOG_FILENAME = "memory_debug.log"

# ═══════════════════════════════════════════════════════════════
# BPF PROGRAM
# ═══════════════════════════════════════════════════════════════

BPF_PROGRAM_TEMPLATE = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/net.h>

#define MAX_HEADER_SIZE 1024
#define MAX_USERNAME_LEN 64
#define MAX_COOKIE_LEN 256
#define MAX_AUTH_LEN 128
#define MAX_REQUEST_ID_LEN 64
#define MAX_REQUESTS_PER_USER 100
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_PRIVATE 0x02
#define MAP_ANONYMOUS 0x20

#define TARGET_PID %d

// ═══════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════

struct conn_tuple_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

struct request_id_key_t {
    char id[MAX_REQUEST_ID_LEN];
};

struct username_key_t {
    char name[MAX_USERNAME_LEN];
};

struct user_info_t {
    char username[MAX_USERNAME_LEN];
    char cookie[MAX_COOKIE_LEN];
    char authorization[MAX_AUTH_LEN];
    u8 has_username;
    u8 has_cookie;
    u8 has_authorization;
};

struct resource_usage_t {
    char request_id[MAX_REQUEST_ID_LEN];
    u32 tid;
    u64 start_time_ns;
    u64 end_time_ns;
    u64 duration_ns;
    u64 cpu_cycles_start;
    u64 cpu_cycles_end;
    u64 cpu_cycles_used;
    u32 memory_kb;
    u64 system_overhead_ns;
    u64 thread_lifetime_ns;
    u64 mmap_bytes;
    u64 mprotect_bytes;
    u64 peak_physical_bytes;
    u8 is_complete;
    u32 src_ip;
    u16 src_port;
    u64 bytes_sent; 
    u64 bytes_recv; 
    u64 disk_read_bytes;
    u64 disk_write_bytes;
};

struct request_entry_t {
    char request_id[MAX_REQUEST_ID_LEN];
    u64 timestamp_ns;
    u32 tid;
    u32 src_ip;
    u16 src_port;
};

struct user_history_t {
    char username[MAX_USERNAME_LEN];
    struct request_entry_t requests[MAX_REQUESTS_PER_USER];
    u32 request_count;
    u64 last_updated_ns;
};

struct ssl_data_event_t {
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 data_len;
    char data[MAX_HEADER_SIZE];
    u8 has_conn_info;
};

struct mem_event_t {
    u64 timestamp_ns;
    u32 tid;
    u32 pid;
    u8 type;
    u64 size_bytes;
    u64 pfn;
    u64 current_total_bytes; 
};

struct exit_event_t {
    u32 tid;
    char request_id[MAX_REQUEST_ID_LEN];
};

struct ssl_read_ex_args_t {
    void *buf;
    void *readbytes_ptr;
};

struct alloc_args_t {
    u64 __unused;
    unsigned long pfn;
    unsigned int order;
    unsigned int gfp_flags;
};

struct free_args_t {
    u64 __unused;
    unsigned long pfn;
    unsigned int order;
};

// ═══════════════════════════════════════════════════════════════
// MAPS
// ═══════════════════════════════════════════════════════════════

BPF_HASH(fd_to_conn, u32, struct conn_tuple_t);
BPF_HASH(tid_to_fd, u64, u32);
BPF_HASH(request_resources, struct request_id_key_t, struct resource_usage_t);
BPF_HASH(tid_to_request_id, u32, struct request_id_key_t);
BPF_HASH(tid_to_thread_start, u32, u64);
BPF_HASH(tid_to_overhead_ns, u32, u64);
BPF_HASH(tid_mmap_bytes, u32, u64);
BPF_HASH(tid_mprotect_bytes, u32, u64);
BPF_HASH(pfn_owner, u64, u32);
BPF_HASH(tid_curr_phys, u32, u64);
BPF_HASH(user_request_history, struct username_key_t, struct user_history_t);
BPF_HASH(active_sock_op, u32, u8); // 1=Recv, 2=Send, 3=DiskRead, 4=DiskWrite

BPF_PERF_OUTPUT(ssl_events);
BPF_PERF_OUTPUT(mem_events);
BPF_PERF_OUTPUT(exit_events);

BPF_HASH(ssl_read_args, u64, void *);
BPF_PERCPU_ARRAY(event_scratch, struct ssl_data_event_t, 1);
BPF_HASH(ssl_read_ex_args, u64, struct ssl_read_ex_args_t);

// ═══════════════════════════════════════════════════════════════
// HELPER: PID FILTER
// ═══════════════════════════════════════════════════════════════
static inline int is_target_process() {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid != TARGET_PID) return 0;
    return 1;
}

static struct sock* get_sock_from_fd(u32 fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = task->files;
    if (files == NULL) return NULL;
    struct fdtable *fdt = files->fdt;
    if (fdt == NULL) return NULL;
    if (fd >= fdt->max_fds) return NULL;
    struct file **fd_array;
    bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    struct file *file;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (file == NULL) return NULL;
    struct socket *sock_obj;
    bpf_probe_read_kernel(&sock_obj, sizeof(sock_obj), &file->private_data);
    if (sock_obj == NULL) return NULL;
    struct sock *sk;
    bpf_probe_read_kernel(&sk, sizeof(sk), &sock_obj->sk);
    return sk;
}

// ═══════════════════════════════════════════════════════════════
// CONNECTION & SYSCALL TRACKING (RECV/SEND/READ/WRITE)
// ═══════════════════════════════════════════════════════════════

// --- ENTER PROBES ---

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
    
    // Mark as RECV (1)
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
            // Socket read - mark as RECV (1)
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
    // Non-socket fd read - mark as DISK_READ (3)
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

    // Mark as SEND (2)
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
            // Socket write - mark as SEND (2)
            u8 type = 2;
            active_sock_op.update(&tid, &type);
            return 0;
        }
    }
    // Non-socket fd write - mark as DISK_WRITE (4)
    if (fd > 2) {
        u8 type = 4;
        active_sock_op.update(&tid, &type);
    }
    return 0;
}

// --- EXIT PROBES (CAPTURE RET VAL - FIXED) ---

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

// ═══════════════════════════════════════════════════════════════
// SSL INTERCEPTION
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

// ═══════════════════════════════════════════════════════════════
// THREAD EXIT TRACKING
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
    
    tid_to_thread_start.delete(&tid);
    tid_to_fd.delete(&pid_tgid);
    tid_to_overhead_ns.delete(&tid);
    tid_to_request_id.delete(&tid);
    tid_curr_phys.delete(&tid);
    active_sock_op.delete(&tid);
    
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// VIRTUAL MEMORY (mmap/mprotect)
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
// PHYSICAL MEMORY (Alloc/Free)
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

    struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
    if (req_id_key != NULL) {
        struct resource_usage_t *usage = request_resources.lookup(req_id_key);
        if (usage != NULL) {
            if (cur_bytes > usage->peak_physical_bytes) {
                usage->peak_physical_bytes = cur_bytes;
            }
        }
    }

    struct mem_event_t ev = {};
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.tid = tid;
    ev.pid = pid;
    ev.type = 1; // ALLOC
    ev.size_bytes = size;
    ev.pfn = pfn;
    ev.current_total_bytes = cur_bytes;
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
    mem_events.perf_submit(args, &ev, sizeof(ev));

    pfn_owner.delete(&pfn);
    return 0;
}
"""

class IntegratedSnifferFull:
    def __init__(self, pid):
        self.pid = pid
        self.bpf = None
        self.request_buffers = {}
        self.request_counter = 0
        self.recorded_requests = [] # Store local copy for final summary
        
        # Prepare Log File
        self.log_file = open(LOG_FILENAME, "w")
        self.log_file.write(f"TIMESTAMP             | TID   | EVENT | SIZE (KB) | CURRENT TID RSS (KB) | PFN\n")
        self.log_file.write("-" * 90 + "\n")

    def ip_to_str(self, ip):
        try:
            return socket.inet_ntoa(struct.pack("<I", ip))
        except Exception:
            return "0.0.0.0"

    def parse_http_headers(self, data):
        try:
            text = data.decode('utf-8', errors='ignore')
            header_end = text.find('\r\n\r\n')
            if header_end == -1:
                header_end = text.find('\n\n')
                if header_end == -1: header_end = len(text)
            return text[:header_end]
        except:
            return ""

    def extract_request_id(self, headers_text):
        for line in headers_text.split('\n'):
            line = line.strip()
            if line.lower().startswith('x-request-id:'):
                return line[13:].strip()[:63]
        first_line = headers_text.split('\n')[0] if headers_text else ""
        match = re.search(r'[?&]id=([^&\s]+)', first_line)
        if match: return match.group(1)[:63]
        self.request_counter += 1
        return f"AUTO_{self.request_counter:06d}"

    def extract_user_info(self, headers_text):
        user_info = {'username': '', 'cookie': '', 'authorization': '',
                     'has_username': False, 'has_cookie': False, 'has_authorization': False}
        try:
            for line in headers_text.split('\n'):
                line = line.strip()
                if line.lower().startswith('cookie:'):
                    cookie_value = line[7:].strip()
                    user_info['cookie'] = cookie_value[:255]
                    user_info['has_cookie'] = True
                    for part in cookie_value.split(';'):
                        part = part.strip()
                        if '=' in part:
                            key, val = part.split('=', 1)
                            if key.lower() in ['user', 'username', 'user_id']:
                                user_info['username'] = val[:63]
                                user_info['has_username'] = True
                                break
                elif line.lower().startswith('authorization:'):
                    auth_value = line[14:].strip()
                    user_info['authorization'] = auth_value[:127]
                    user_info['has_authorization'] = True
                    if auth_value.lower().startswith('basic '):
                        try:
                            import base64
                            decoded = base64.b64decode(auth_value[6:]).decode('utf-8', 'ignore')
                            if ':' in decoded:
                                user_info['username'] = decoded.split(':')[0][:63]
                                user_info['has_username'] = True
                        except: pass
                elif not user_info['has_username']:
                    if line.lower().startswith('x-user:') or line.lower().startswith('x-username:'):
                        colon_pos = line.find(':')
                        if colon_pos > 0:
                            user_info['username'] = line[colon_pos+1:].strip()[:63]
                            user_info['has_username'] = True
        except: pass
        return user_info

    def update_user_history(self, username, request_id, tid, src_ip, src_port):
        if not username: return
        try:
            user_history_map = self.bpf.get_table("user_request_history")
            username_key = user_history_map.Key(name=username.encode('utf-8')[:63])
            try:
                history = user_history_map[username_key]
            except KeyError:
                history = user_history_map.Leaf(username=username.encode('utf-8')[:63], request_count=0)
            
            idx = history.request_count
            if idx >= 100:
                for i in range(99): history.requests[i] = history.requests[i + 1]
                idx = 99
            else:
                history.request_count += 1
            
            history.requests[idx].request_id = request_id.encode('utf-8')[:63]
            history.requests[idx].timestamp_ns = int(time.time_ns())
            history.requests[idx].tid = tid
            history.requests[idx].src_ip = src_ip
            history.requests[idx].src_port = src_port
            history.last_updated_ns = int(time.time_ns())
            user_history_map[username_key] = history
            self.display_user_history(username, history)
        except Exception: pass

    def update_resource_tracking(self, request_id, tid, src_ip, src_port):
        try:
            tid_to_req_map = self.bpf.get_table("tid_to_request_id")
            resource_map = self.bpf.get_table("request_resources")
            
            tid_mmap_map = self.bpf.get_table("tid_mmap_bytes")
            tid_mprot_map = self.bpf.get_table("tid_mprotect_bytes")
            tid_phys_map = self.bpf.get_table("tid_curr_phys")
            
            acc_mmap = 0
            acc_mprot = 0
            acc_phys = 0
            try: acc_mmap = tid_mmap_map[ctypes.c_uint(tid)].value
            except: pass
            try: acc_mprot = tid_mprot_map[ctypes.c_uint(tid)].value
            except: pass
            try: acc_phys = tid_phys_map[ctypes.c_uint(tid)].value
            except: pass
            
            # Check for temp ID
            temp_request_id = None
            try:
                existing_key = tid_to_req_map[ctypes.c_uint(tid)]
                temp_request_id = existing_key.id.decode('utf-8', 'ignore').rstrip('\x00')
            except KeyError: pass
            
            if temp_request_id and temp_request_id != request_id and temp_request_id.startswith(f"TID_{tid}_"):
                try:
                    temp_key = resource_map.Key(id=temp_request_id.encode('utf-8')[:63])
                    temp_usage = resource_map[temp_key]
                    
                    usage = resource_map.Leaf(
                        request_id=request_id.encode('utf-8')[:63],
                        tid=tid,
                        start_time_ns=temp_usage.start_time_ns,
                        cpu_cycles_start=temp_usage.cpu_cycles_start,
                        memory_kb=self._get_tid_memory_kb(tid),
                        is_complete=0,
                        system_overhead_ns=0,
                        thread_lifetime_ns=0,
                        mmap_bytes=acc_mmap,
                        mprotect_bytes=acc_mprot,
                        peak_physical_bytes=max(temp_usage.peak_physical_bytes, acc_phys),
                        src_ip=src_ip,
                        src_port=src_port,
                        bytes_sent=temp_usage.bytes_sent,
                        bytes_recv=temp_usage.bytes_recv,
                        disk_read_bytes=temp_usage.disk_read_bytes,
                        disk_write_bytes=temp_usage.disk_write_bytes
                    )
                    req_key = resource_map.Key(id=request_id.encode('utf-8')[:63])
                    resource_map[req_key] = usage
                    
                    req_id_key_val = tid_to_req_map.Leaf(id=request_id.encode('utf-8')[:63])
                    tid_to_req_map[ctypes.c_uint(tid)] = req_id_key_val
                    del resource_map[temp_key]
                    return
                except KeyError: pass

            req_id_key_val = tid_to_req_map.Leaf(id=request_id.encode('utf-8')[:63])
            tid_to_req_map[ctypes.c_uint(tid)] = req_id_key_val
            
            usage = resource_map.Leaf(
                request_id=request_id.encode('utf-8')[:63],
                tid=tid,
                start_time_ns=int(time.time_ns()),
                cpu_cycles_start=int(time.time_ns()),
                memory_kb=self._get_tid_memory_kb(tid),
                is_complete=0,
                system_overhead_ns=0,
                thread_lifetime_ns=0,
                mmap_bytes=acc_mmap,
                mprotect_bytes=acc_mprot,
                peak_physical_bytes=acc_phys,
                src_ip=src_ip,
                src_port=src_port,
                bytes_sent=0,
                bytes_recv=0,
                disk_read_bytes=0,
                disk_write_bytes=0
            )
            req_key = resource_map.Key(id=request_id.encode('utf-8')[:63])
            resource_map[req_key] = usage
        except Exception as e: print(f"Error tracking: {e}")

    def complete_resource_tracking(self, request_id, thread_exit=False):
        try:
            resource_map = self.bpf.get_table("request_resources")
            req_key = resource_map.Key(id=request_id.encode('utf-8')[:63])
            usage = resource_map[req_key]

            completion_time_ns = int(time.time_ns())
            usage.end_time_ns = completion_time_ns
            usage.duration_ns = usage.end_time_ns - usage.start_time_ns
            usage.cpu_cycles_end = usage.end_time_ns # Approx
            usage.cpu_cycles_used = usage.cpu_cycles_end - usage.cpu_cycles_start

            try:
                overhead_map = self.bpf.get_table("tid_to_overhead_ns")
                usage.system_overhead_ns = overhead_map[ctypes.c_uint(usage.tid)].value
            except KeyError: pass

            if usage.thread_lifetime_ns == 0:
                 try:
                    thread_start_map = self.bpf.get_table("tid_to_thread_start")
                    thread_start_ns = thread_start_map[ctypes.c_uint(usage.tid)].value
                    usage.thread_lifetime_ns = completion_time_ns - thread_start_ns
                 except: 
                    usage.thread_lifetime_ns = usage.duration_ns
            
            usage.memory_kb = max(usage.memory_kb, self._get_tid_memory_kb(usage.tid))
            usage.is_complete = 1
            resource_map[req_key] = usage
            
            # Re-read to ensure we have kernel updates
            usage = resource_map[req_key]
            
            # Save to python list
            record = {
                'id': request_id,
                'ts': datetime.fromtimestamp(usage.start_time_ns / 1e9).strftime('%H:%M:%S'),
                'tid': usage.tid,
                'src': f"{self.ip_to_str(usage.src_ip)}:{usage.src_port}",
                'mmap': usage.mmap_bytes / 1024.0,
                'mprot': usage.mprotect_bytes / 1024.0,
                'peak': usage.peak_physical_bytes / 1024.0,
                'overhead': usage.system_overhead_ns,
                'latency': usage.duration_ns / 1_000_000.0,
                'send': usage.bytes_sent / 1024.0,
                'recv': usage.bytes_recv / 1024.0,
                'disk_rd': usage.disk_read_bytes / 1024.0,
                'disk_wr': usage.disk_write_bytes / 1024.0
            }
            
            # Only add to list if not present (or update it)
            found = False
            for i, r in enumerate(self.recorded_requests):
                if r['id'] == request_id:
                    self.recorded_requests[i] = record
                    found = True
                    break
            if not found:
                self.recorded_requests.append(record)

            if thread_exit:
                print(f"\n[Thread Exit] Stats for Request: {request_id}")
                self.print_table_header()
                self.print_table_row(record)
            
        except KeyError: pass
        except Exception as e: print(f"Error completing: {e}")

    def print_table_header(self):
        print("-" * 205)
        print(f"{'Request-ID':<20} | {'Timestamp':<10} | {'Thread':<7} | {'Source IP:Port':<21} | {'MMap(KB)':>10} | {'Mprot(KB)':>10} | {'Peak Phy(KB)':>13} | {'Send(KB)':>10} | {'Recv(KB)':>10} | {'DiskRd(KB)':>11} | {'DiskWr(KB)':>11} | {'Overhead(ns)':>13} | {'Latency(ms)':>11}")
        print("-" * 205)

    def print_table_row(self, r):
        print(f"{r['id']:<20} | {r['ts']:<10} | {r['tid']:<7} | {r['src']:<21} | {r['mmap']:>10.1f} | {r['mprot']:>10.1f} | {r['peak']:>13.1f} | {r['send']:>10.1f} | {r['recv']:>10.1f} | {r['disk_rd']:>11.1f} | {r['disk_wr']:>11.1f} | {r['overhead']:>13,d} | {r['latency']:>11.2f}")

    def _get_tid_memory_kb(self, tid):
        try:
            with open(f"/proc/{self.pid}/task/{tid}/status", 'r') as f:
                for line in f:
                    if line.startswith('VmRSS:'): return int(line.split()[1])
        except: return 0
        return 0

    def display_user_history(self, username, history):
        print(f"\n--- User History: {username} ---")
        print(f"| {'#':<3} | {'Request ID':<20} | {'Thread':<7} | {'Overhead(ns)':>13} | {'Peak RSS(MB)':>13} |")
        print("-" * 75)
        if history.request_count > 0:
            resource_map = self.bpf.get_table("request_resources")
            for i in range(history.request_count):
                req_entry = history.requests[i]
                req_id = req_entry.request_id.decode('utf-8', 'ignore').rstrip('\x00')
                if not req_id: continue
                overhead_ns = 0
                peak_mem = 0
                try:
                    req_key = resource_map.Key(id=req_id.encode('utf-8')[:63])
                    usage = resource_map[req_key]
                    overhead_ns = usage.system_overhead_ns
                    peak_mem = usage.peak_physical_bytes / 1024 / 1024
                except KeyError: pass
                print(f"| {i+1:<3} | {req_id:<20} | {req_entry.tid:<7} | {overhead_ns:>13,d} | {peak_mem:>13.2f} |")
        print()

    def handle_ssl_event(self, cpu, data, size):
        event = self.bpf["ssl_events"].event(data)
        tid = event.tid
        
        if tid not in self.request_buffers:
            temp_request_id = f"TID_{tid}_{int(time.time_ns())}"
            self.request_buffers[tid] = {
                'data': b'', 'pid': event.pid, 'tid': tid,
                'comm': event.comm.decode('utf-8', 'ignore'),
                'has_conn_info': event.has_conn_info, 'src_ip': event.src_ip,
                'dst_ip': event.dst_ip, 'src_port': event.src_port, 'dst_port': event.dst_port,
                'timestamp': time.time()
            }
            # Initialize tracking so Alloc/Mmap are caught early
            try:
                tid_to_req_map = self.bpf.get_table("tid_to_request_id")
                req_id_key_val = tid_to_req_map.Leaf(id=temp_request_id.encode('utf-8')[:63])
                tid_to_req_map[ctypes.c_uint(tid)] = req_id_key_val
                
                resource_map = self.bpf.get_table("request_resources")
                usage = resource_map.Leaf(
                    request_id=temp_request_id.encode('utf-8')[:63],
                    tid=tid,
                    start_time_ns=int(time.time_ns()),
                    peak_physical_bytes=0,
                    src_ip=event.src_ip,
                    src_port=event.src_port,
                    bytes_sent=0,
                    bytes_recv=0,
                    disk_read_bytes=0,
                    disk_write_bytes=0
                )
                req_key = resource_map.Key(id=temp_request_id.encode('utf-8')[:63])
                resource_map[req_key] = usage
            except: pass
        
        self.request_buffers[tid]['data'] += bytes(event.data[:event.data_len])
        if event.has_conn_info:
            self.request_buffers[tid].update({
                'has_conn_info': True, 'src_ip': event.src_ip, 'dst_ip': event.dst_ip,
                'src_port': event.src_port, 'dst_port': event.dst_port
            })
        
        full_data = self.request_buffers[tid]['data']
        if b'\r\n\r\n' in full_data or b'\n\n' in full_data:
            if full_data.startswith((b'GET', b'POST', b'PUT', b'DELETE')):
                self.display_complete_request(tid)
            del self.request_buffers[tid]

    def display_complete_request(self, tid):
        req = self.request_buffers[tid]
        headers = self.parse_http_headers(req['data'])
        request_id = self.extract_request_id(headers)
        user_info = self.extract_user_info(headers)
        
        if user_info['has_username'] and req['has_conn_info']:
            self.update_user_history(user_info['username'], request_id, tid, req['src_ip'], req['src_port'])
        
        self.update_resource_tracking(request_id, tid, req['src_ip'], req['src_port'])
        self.complete_resource_tracking(request_id)

    def handle_mem_event(self, cpu, data, size):
        ev = self.bpf["mem_events"].event(data)
        ts = datetime.fromtimestamp(ev.timestamp_ns / 1e9).strftime('%H:%M:%S.%f')
        etype = "ALLOC" if ev.type == 1 else "FREE "
        size_kb = ev.size_bytes / 1024
        total_kb = ev.current_total_bytes / 1024
        log_line = f"{ts} | {ev.tid:<5} | {etype} | {size_kb:>9.2f} | {total_kb:>20.2f} | {ev.pfn}\n"
        self.log_file.write(log_line)
        self.log_file.flush()

    def handle_exit_event(self, cpu, data, size):
        ev = self.bpf["exit_events"].event(data)
        req_id = ev.request_id.decode('utf-8', 'ignore').rstrip('\x00')
        self.complete_resource_tracking(req_id, thread_exit=True)

    def run(self):
        print("="*60)
        print("🔍 INTEGRATED FULL SNIFFER (FIXED + IO)".center(60))
        print("="*60)
        print(f"Target PID: {self.pid}")
        print(f"Log File:   {os.path.abspath(LOG_FILENAME)}")
        print("Initializing BPF... (Please wait)")
        
        self.bpf = BPF(text=BPF_PROGRAM_TEMPLATE % self.pid)
        ssl_lib = BPF.find_library("ssl") or "/usr/lib/libssl.so.3"
        
        self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read", fn_name="probe_ssl_read_enter")
        self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read", fn_name="probe_ssl_read_exit")
        try:
            self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read_ex", fn_name="probe_ssl_read_ex_enter")
            self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read_ex", fn_name="probe_ssl_read_ex_exit")
        except: pass
        
        print("✓ BPF Loaded. Monitoring...")
        # self.print_table_header()
        
        self.bpf["ssl_events"].open_perf_buffer(self.handle_ssl_event)
        self.bpf["mem_events"].open_perf_buffer(self.handle_mem_event)
        self.bpf["exit_events"].open_perf_buffer(self.handle_exit_event)
        
        while True:
            try:
                self.bpf.perf_buffer_poll()
            except KeyboardInterrupt:
                print("\n\n" + "="*205)
                print("FINAL SESSION SUMMARY".center(205))
                self.print_table_header()
                for r in self.recorded_requests:
                    self.print_table_row(r)
                print("="*205)
                print(f"Memory log saved to: {LOG_FILENAME}")
                self.log_file.close()
                break

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root.")
        sys.exit(1)
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pid", type=int, required=True, help="Target PID")
    args = parser.parse_args()
    
    IntegratedSnifferFull(args.pid).run()