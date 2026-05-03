# #!/usr/bin/env python3
# """
# Integrated HTTPS Server Sniffer
# ================================
# Combines all tracking features:
# 1. Connection attribution (TID → FD → Connection)
# 2. User information extraction (username, cookie, authorization)
# 3. Resource usage tracking (CPU, memory, time per request)
# 4. User request history (all requests per user)

# Usage: sudo python3 integrated_sniffer.py
# """

# from bcc import BPF
# import socket
# import struct
# import ctypes
# import time
# import re
# import os

# # Combined eBPF Program
# BPF_PROGRAM = """
# #include <uapi/linux/ptrace.h>
# #include <net/sock.h>
# #include <net/inet_sock.h>
# #include <linux/sched.h>
# #include <linux/fdtable.h>
# #include <linux/fs.h>
# #include <linux/socket.h>
# #include <linux/net.h>

# #define MAX_HEADER_SIZE 1024
# #define MAX_USERNAME_LEN 64
# #define MAX_COOKIE_LEN 256
# #define MAX_AUTH_LEN 128
# #define MAX_REQUEST_ID_LEN 64
# #define MAX_REQUESTS_PER_USER 100

# // ═══════════════════════════════════════════════════════════════
# // DATA STRUCTURES
# // ═══════════════════════════════════════════════════════════════

# // Connection 4-tuple
# struct conn_tuple_t {
#     u32 src_ip;
#     u32 dst_ip;
#     u16 src_port;
#     u16 dst_port;
# };

# // Key structures (struct wrappers for arrays)
# struct request_id_key_t {
#     char id[MAX_REQUEST_ID_LEN];
# };

# struct username_key_t {
#     char name[MAX_USERNAME_LEN];
# };

# // User information from HTTP headers
# struct user_info_t {
#     char username[MAX_USERNAME_LEN];
#     char cookie[MAX_COOKIE_LEN];
#     char authorization[MAX_AUTH_LEN];
#     u8 has_username;
#     u8 has_cookie;
#     u8 has_authorization;
# };

# // Resource usage per request
# struct resource_usage_t {
#     char request_id[MAX_REQUEST_ID_LEN];
#     u32 tid;
#     u64 start_time_ns;
#     u64 end_time_ns;
#     u64 duration_ns;
#     u64 cpu_cycles_start;
#     u64 cpu_cycles_end;
#     u64 cpu_cycles_used;
#     u32 memory_kb;            // Resident memory (approx., userspace filled)
#     u64 system_overhead_ns;    // Time spent in our eBPF/userspace tracking
#     u64 thread_lifetime_ns;    // Estimated lifetime of thread processing this request
#     u8 is_complete;
# };

# // Single request entry in user history
# struct request_entry_t {
#     char request_id[MAX_REQUEST_ID_LEN];
#     u64 timestamp_ns;
#     u32 tid;
#     u32 src_ip;
#     u16 src_port;
# };

# // User request history
# struct user_history_t {
#     char username[MAX_USERNAME_LEN];
#     struct request_entry_t requests[MAX_REQUESTS_PER_USER];
#     u32 request_count;
#     u64 last_updated_ns;
# };

# // Event sent to userspace
# struct ssl_data_event_t {
#     u32 pid;
#     u32 tid;
#     char comm[TASK_COMM_LEN];
#     u32 src_ip;
#     u32 dst_ip;
#     u16 src_port;
#     u16 dst_port;
#     u32 data_len;
#     char data[MAX_HEADER_SIZE];
#     u8 has_conn_info;
# };

# // ═══════════════════════════════════════════════════════════════
# // PRIMARY MAPS
# // ═══════════════════════════════════════════════════════════════

# // 1. Connection attribution
# BPF_HASH(fd_to_conn, u32, struct conn_tuple_t);
# BPF_HASH(tid_to_fd, u64, u32);

# // 2. User information
# BPF_HASH(tid_to_user_info, u32, struct user_info_t);

# // 3. Resource tracking
# BPF_HASH(request_resources, struct request_id_key_t, struct resource_usage_t);
# BPF_HASH(tid_to_request_id, u32, struct request_id_key_t);
# BPF_HASH(tid_to_thread_start, u32, u64);  // Track when thread first starts processing (first recv/read)
# // Per-TID cumulative overhead incurred by our probes (in ns)
# BPF_HASH(tid_to_overhead_ns, u32, u64);

# // 4. User request history
# BPF_HASH(user_request_history, struct username_key_t, struct user_history_t);

# // Output channel
# BPF_PERF_OUTPUT(ssl_events);

# // Temporary storage
# BPF_HASH(ssl_read_args, u64, void *);
# BPF_PERCPU_ARRAY(event_scratch, struct ssl_data_event_t, 1);

# // ═══════════════════════════════════════════════════════════════
# // HELPER: Get socket from FD
# // ═══════════════════════════════════════════════════════════════

# static struct sock* get_sock_from_fd(u32 fd) {
#     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
#     struct files_struct *files = task->files;
#     if (files == NULL) return NULL;
    
#     struct fdtable *fdt = files->fdt;
#     if (fdt == NULL) return NULL;
    
#     if (fd >= fdt->max_fds) return NULL;
    
#     struct file **fd_array;
#     bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    
#     struct file *file;
#     bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
#     if (file == NULL) return NULL;
    
#     struct socket *sock_obj;
#     bpf_probe_read_kernel(&sock_obj, sizeof(sock_obj), &file->private_data);
#     if (sock_obj == NULL) return NULL;
    
#     struct sock *sk;
#     bpf_probe_read_kernel(&sk, sizeof(sk), &sock_obj->sk);
    
#     return sk;
# }

# // ═══════════════════════════════════════════════════════════════
# // CONNECTION TRACKING: First recv() establishes FD→Connection
# // ═══════════════════════════════════════════════════════════════

# TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 fd = (u32)args->fd;
#     u64 t0 = bpf_ktime_get_ns();
    
#     // ALWAYS recompute connection tuple for this FD to avoid stale cache
#     struct sock *sk = get_sock_from_fd(fd);
#     if (sk == NULL) return 0;
    
#     u16 family;
#     bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
#     if (family != AF_INET) return 0;
    
#     struct conn_tuple_t conn = {};
#     // Prefer inet_sock fields for reliability across kernels
#     struct inet_sock *inet = (struct inet_sock *)sk;
#     u16 sport_be = 0, dport_be = 0;
#     bpf_probe_read_kernel(&conn.src_ip, sizeof(u32), &inet->inet_daddr);      // client IP
#     bpf_probe_read_kernel(&conn.dst_ip, sizeof(u32), &inet->inet_rcv_saddr);  // server IP
#     bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);         // local/server port
#     bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);         // remote/client port
#     conn.src_port = bpf_ntohs(dport_be);  // client port
#     conn.dst_port = bpf_ntohs(sport_be);  // server port
    
#     // Update cache on every recv/read; FD numbers can be reused
#     fd_to_conn.update(&fd, &conn);
#     tid_to_fd.update(&pid_tgid, &fd);
    
#     // Track thread start time (first time we see this TID processing)
#     u32 tid = (u32)pid_tgid;
#     u64 *existing_start = tid_to_thread_start.lookup(&tid);
#     if (existing_start == NULL) {
#         u64 start_time = bpf_ktime_get_ns();
#         tid_to_thread_start.update(&tid, &start_time);
#     }
    
#     // Accumulate probe overhead for this TID
#     u32 tid_acc = (u32)pid_tgid;
#     u64 t1 = bpf_ktime_get_ns();
#     u64 delta = t1 - t0;
#     u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
#     if (acc_ptr) {
#         u64 acc = *acc_ptr + delta;
#         tid_to_overhead_ns.update(&tid_acc, &acc);
#     } else {
#         tid_to_overhead_ns.update(&tid_acc, &delta);
#     }
#     return 0;
# }

# TRACEPOINT_PROBE(syscalls, sys_enter_read) {
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 fd = (u32)args->fd;
#     u64 t0 = bpf_ktime_get_ns();
    
#     // ALWAYS recompute connection tuple for this FD to avoid stale cache
#     struct sock *sk = get_sock_from_fd(fd);
#     if (sk == NULL) return 0;
    
#     u16 family;
#     bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
#     if (family != AF_INET) return 0;
    
#     struct conn_tuple_t conn = {};
#     struct inet_sock *inet = (struct inet_sock *)sk;
#     u16 sport_be = 0, dport_be = 0;
#     bpf_probe_read_kernel(&conn.src_ip, sizeof(u32), &inet->inet_daddr);
#     bpf_probe_read_kernel(&conn.dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
#     bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
#     bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
#     conn.src_port = bpf_ntohs(dport_be);
#     conn.dst_port = bpf_ntohs(sport_be);
    
#     fd_to_conn.update(&fd, &conn);
#     tid_to_fd.update(&pid_tgid, &fd);
    
#     // Track thread start time (first time we see this TID processing)
#     u32 tid = (u32)pid_tgid;
#     u64 *existing_start = tid_to_thread_start.lookup(&tid);
#     if (existing_start == NULL) {
#         u64 start_time = bpf_ktime_get_ns();
#         tid_to_thread_start.update(&tid, &start_time);
#     }
    
#     // Accumulate probe overhead for this TID
#     u32 tid_acc = (u32)pid_tgid;
#     u64 t1 = bpf_ktime_get_ns();
#     u64 delta = t1 - t0;
#     u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
#     if (acc_ptr) {
#         u64 acc = *acc_ptr + delta;
#         tid_to_overhead_ns.update(&tid_acc, &acc);
#     } else {
#         tid_to_overhead_ns.update(&tid_acc, &delta);
#     }
#     return 0;
# }

# // ═══════════════════════════════════════════════════════════════
# // SSL INTERCEPTION
# // ═══════════════════════════════════════════════════════════════

# int probe_ssl_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     ssl_read_args.update(&pid_tgid, &buf);
#     return 0;
# }

# int probe_ssl_read_exit(struct pt_regs *ctx) {
#     u64 t0 = bpf_ktime_get_ns();
#     int ret = PT_REGS_RC(ctx);
#     if (ret <= 0) return 0;
    
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 pid = pid_tgid >> 32;
#     u32 tid = (u32)pid_tgid;
    
#     void **buf_ptr = ssl_read_args.lookup(&pid_tgid);
#     if (buf_ptr == NULL) return 0;
#     void *buf = *buf_ptr;
#     ssl_read_args.delete(&pid_tgid);
    
#     u32 zero = 0;
#     struct ssl_data_event_t *evt = event_scratch.lookup(&zero);
#     if (evt == NULL) return 0;
    
#     evt->pid = pid;
#     evt->tid = tid;
#     evt->has_conn_info = 0;
#     evt->src_ip = 0;
#     evt->dst_ip = 0;
#     evt->src_port = 0;
#     evt->dst_port = 0;
    
#     bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
#     u32 copy_len = (u32)ret;
#     if (copy_len > MAX_HEADER_SIZE) copy_len = MAX_HEADER_SIZE;
#     bpf_probe_read_user(&evt->data, copy_len, buf);
#     evt->data_len = copy_len;
    
#     // Resolve connection on EVERY SSL read using current FD
#     u32 *fd_ptr = tid_to_fd.lookup(&pid_tgid);
#     if (fd_ptr != NULL) {
#         u32 fd = *fd_ptr;
#         struct sock *sk = get_sock_from_fd(fd);
#         if (sk != NULL) {
#             u16 family;
#             bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
#             if (family == AF_INET) {
#                 struct inet_sock *inet = (struct inet_sock *)sk;
#                 u16 sport_be = 0, dport_be = 0;
#                 bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_daddr);
#                 bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
#                 bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
#                 bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
#                 evt->src_port = bpf_ntohs(dport_be);
#                 evt->dst_port = bpf_ntohs(sport_be);
#                 evt->has_conn_info = 1;
#             }
#         }
#     }
    
#     ssl_events.perf_submit(ctx, evt, sizeof(*evt));

#     // Accumulate probe overhead for this TID
#     u32 tid_acc = (u32)pid_tgid;
#     u64 t1 = bpf_ktime_get_ns();
#     u64 delta = t1 - t0;
#     u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
#     if (acc_ptr) {
#         u64 acc = *acc_ptr + delta;
#         tid_to_overhead_ns.update(&tid_acc, &acc);
#     } else {
#         tid_to_overhead_ns.update(&tid_acc, &delta);
#     }
#     return 0;
# }

# // SSL_read_ex support
# struct ssl_read_ex_args_t {
#     void *buf;
#     void *readbytes_ptr;
# };

# BPF_HASH(ssl_read_ex_args, u64, struct ssl_read_ex_args_t);

# int probe_ssl_read_ex_enter(struct pt_regs *ctx, void *ssl, void *buf,
#                              unsigned long num, void *readbytes) {
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     struct ssl_read_ex_args_t args = {.buf = buf, .readbytes_ptr = readbytes};
#     ssl_read_ex_args.update(&pid_tgid, &args);
#     return 0;
# }

# int probe_ssl_read_ex_exit(struct pt_regs *ctx) {
#     u64 t0 = bpf_ktime_get_ns();
#     int ret = PT_REGS_RC(ctx);
#     if (ret != 1) return 0;
    
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 pid = pid_tgid >> 32;
#     u32 tid = (u32)pid_tgid;
    
#     struct ssl_read_ex_args_t *args = ssl_read_ex_args.lookup(&pid_tgid);
#     if (args == NULL) return 0;
    
#     unsigned long bytes_read = 0;
#     bpf_probe_read_user(&bytes_read, sizeof(bytes_read), args->readbytes_ptr);
#     if (bytes_read <= 0) {
#         ssl_read_ex_args.delete(&pid_tgid);
#         return 0;
#     }
    
#     void *buf = args->buf;
#     ssl_read_ex_args.delete(&pid_tgid);
    
#     u32 zero = 0;
#     struct ssl_data_event_t *evt = event_scratch.lookup(&zero);
#     if (evt == NULL) return 0;
    
#     evt->pid = pid;
#     evt->tid = tid;
#     evt->has_conn_info = 0;
#     evt->src_ip = 0;
#     evt->dst_ip = 0;
#     evt->src_port = 0;
#     evt->dst_port = 0;
    
#     bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
#     u32 copy_len = (u32)bytes_read;
#     if (copy_len > MAX_HEADER_SIZE) copy_len = MAX_HEADER_SIZE;
#     bpf_probe_read_user(&evt->data, copy_len, buf);
#     evt->data_len = copy_len;
    
#     u32 *fd_ptr = tid_to_fd.lookup(&pid_tgid);
#     if (fd_ptr != NULL) {
#         u32 fd = *fd_ptr;
#         struct sock *sk = get_sock_from_fd(fd);
#         if (sk != NULL) {
#             u16 family;
#             bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
#             if (family == AF_INET) {
#                 struct inet_sock *inet = (struct inet_sock *)sk;
#                 u16 sport_be = 0, dport_be = 0;
#                 bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_daddr);
#                 bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
#                 bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
#                 bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
#                 evt->src_port = bpf_ntohs(dport_be);
#                 evt->dst_port = bpf_ntohs(sport_be);
#                 evt->has_conn_info = 1;
#             }
#         }
#     }
    
#     ssl_events.perf_submit(ctx, evt, sizeof(*evt));

#     // Accumulate probe overhead for this TID
#     u32 tid_acc = (u32)pid_tgid;
#     u64 t1 = bpf_ktime_get_ns();
#     u64 delta = t1 - t0;
#     u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
#     if (acc_ptr) {
#         u64 acc = *acc_ptr + delta;
#         tid_to_overhead_ns.update(&tid_acc, &acc);
#     } else {
#         tid_to_overhead_ns.update(&tid_acc, &delta);
#     }
#     return 0;
# }

# // ═══════════════════════════════════════════════════════════════
# // THREAD EXIT TRACKING: Update thread lifetime when thread exits
# // ═══════════════════════════════════════════════════════════════

# TRACEPOINT_PROBE(sched, sched_process_exit) {
#     // This fires when a process/thread exits
#     // Get the TID (in Linux, threads are processes, so this works for threads too)
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 tid = (u32)pid_tgid;
    
#     // Look up thread start time
#     u64 *thread_start_ns = tid_to_thread_start.lookup(&tid);
#     if (thread_start_ns == NULL) return 0;  // Not a thread we're tracking
    
#     // Get current time (when thread is exiting)
#     u64 exit_time_ns = bpf_ktime_get_ns();
    
#     // Calculate final thread lifetime
#     u64 lifetime_ns = exit_time_ns - *thread_start_ns;
    
#     // Find the request associated with this TID
#     struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
#     if (req_id_key != NULL) {
#         // Update the resource_usage entry with final thread lifetime
#         struct resource_usage_t *usage = request_resources.lookup(req_id_key);
#         if (usage != NULL) {
#             // Update with final thread lifetime (thread has now exited)
#             usage->thread_lifetime_ns = lifetime_ns;
#             // Note: is_complete is managed by userspace resource tracking, not here
#         }
#     }
    
#     // Clean up thread tracking maps
#     tid_to_thread_start.delete(&tid);
#     tid_to_fd.delete(&pid_tgid);
#     tid_to_overhead_ns.delete(&tid);
    
#     return 0;
# }
# """

# class IntegratedSniffer:
#     def __init__(self):
#         self.bpf = None
#         self.request_buffers = {}
#         self.last_cleanup = 0
#         self.request_counter = 0
    
#     def ip_to_str(self, ip):
#         """Convert IPv4 from u32 to dotted-quad string (handles endianness)."""
#         try:
#             # Many kernels deliver sk addresses read into u32 that appear in host
#             # order on little-endian machines. Use little-endian packing which
#             # renders 127.0.0.1 correctly when the raw value is 0x0100007f.
#             return socket.inet_ntoa(struct.pack("<I", ip))
#         except Exception:
#             return "0.0.0.0"
    
#     def parse_http_headers(self, data):
#         """Parse HTTP headers"""
#         try:
#             text = data.decode('utf-8', errors='ignore')
#             header_end = text.find('\r\n\r\n')
#             if header_end == -1:
#                 header_end = text.find('\n\n')
#                 if header_end == -1:
#                     header_end = len(text)
#             return text[:header_end]
#         except:
#             return ""
    
#     def extract_request_id(self, headers_text):
#         """Extract or generate request ID"""
#         # Try to find X-Request-ID header
#         for line in headers_text.split('\n'):
#             line = line.strip()
#             if line.lower().startswith('x-request-id:'):
#                 return line[13:].strip()[:63]
        
#         # Try to extract from query params (e.g., ?id=REQ001)
#         first_line = headers_text.split('\n')[0] if headers_text else ""
#         match = re.search(r'[?&]id=([^&\s]+)', first_line)
#         if match:
#             return match.group(1)[:63]
        
#         # Generate unique ID
#         self.request_counter += 1
#         return f"AUTO_{self.request_counter:06d}"
    
#     def extract_user_info(self, headers_text):
#         """Extract username, cookie, and authorization from headers"""
#         user_info = {
#             'username': '',
#             'cookie': '',
#             'authorization': '',
#             'has_username': False,
#             'has_cookie': False,
#             'has_authorization': False
#         }
        
#         try:
#             for line in headers_text.split('\n'):
#                 line = line.strip()
                
#                 if line.lower().startswith('cookie:'):
#                     cookie_value = line[7:].strip()
#                     user_info['cookie'] = cookie_value[:255]
#                     user_info['has_cookie'] = True
                    
#                     # Extract username from cookie
#                     for part in cookie_value.split(';'):
#                         part = part.strip()
#                         if '=' in part:
#                             key, val = part.split('=', 1)
#                             if key.lower() in ['user', 'username', 'user_id']:
#                                 user_info['username'] = val[:63]
#                                 user_info['has_username'] = True
#                                 break
                
#                 elif line.lower().startswith('authorization:'):
#                     auth_value = line[14:].strip()
#                     user_info['authorization'] = auth_value[:127]
#                     user_info['has_authorization'] = True
                    
#                     if auth_value.lower().startswith('basic '):
#                         try:
#                             import base64
#                             encoded = auth_value[6:]
#                             decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
#                             if ':' in decoded:
#                                 username = decoded.split(':')[0]
#                                 user_info['username'] = username[:63]
#                                 user_info['has_username'] = True
#                         except:
#                             pass
                
#                 elif not user_info['has_username']:
#                     if line.lower().startswith('x-user:') or line.lower().startswith('x-username:'):
#                         colon_pos = line.find(':')
#                         if colon_pos > 0:
#                             username = line[colon_pos+1:].strip()
#                             user_info['username'] = username[:63]
#                             user_info['has_username'] = True
#         except:
#             pass
        
#         return user_info
    
#     def update_user_history(self, username, request_id, tid, src_ip, src_port):
#         """Add request to user's history and display"""
#         if not username:
#             return
        
#         try:
#             user_history_map = self.bpf.get_table("user_request_history")
            
#             # Create username key struct
#             username_key = user_history_map.Key()
#             username_key.name = username.encode('utf-8')[:63] + b'\x00'
            
#             try:
#                 history = user_history_map[username_key]
#                 request_count = history.request_count
#             except KeyError:
#                 history = user_history_map.Leaf()
#                 history.username = username.encode('utf-8')[:63] + b'\x00'
#                 history.request_count = 0
#                 request_count = 0
            
#             idx = request_count
#             if idx >= 100:
#                 # Shift array
#                 for i in range(99):
#                     history.requests[i] = history.requests[i + 1]
#                 idx = 99
#             else:
#                 history.request_count += 1
            
#             # Add new request
#             history.requests[idx].request_id = request_id.encode('utf-8')[:63] + b'\x00'
#             history.requests[idx].timestamp_ns = int(time.time() * 1_000_000_000)
#             history.requests[idx].tid = tid
#             history.requests[idx].src_ip = src_ip
#             history.requests[idx].src_port = src_port
#             history.last_updated_ns = int(time.time() * 1_000_000_000)
            
#             user_history_map[username_key] = history
            
#             # Display updated history
#             self.display_user_history(username, history)
            
#         except Exception as e:
#             print(f"  [⚠] Error updating user history: {e}")
    
#     def update_resource_tracking(self, request_id, tid, first_ssl_arrival_ns=None):
#         """Track resource usage for this request"""
#         try:
#             tid_to_req_map = self.bpf.get_table("tid_to_request_id")
#             resource_map = self.bpf.get_table("request_resources")
            
#             # Create request ID key struct
#             req_id_key = tid_to_req_map.Leaf()
#             req_id_key.id = request_id.encode('utf-8')[:63] + b'\x00'
            
#             # Store TID → Request ID
#             tid_key = tid_to_req_map.Key(tid)
#             tid_to_req_map[tid_key] = req_id_key
            
#             # Initialize resource tracking
#             usage = resource_map.Leaf()
#             usage.request_id = request_id.encode('utf-8')[:63] + b'\x00'
#             usage.tid = tid
#             usage.start_time_ns = int(time.time() * 1_000_000_000)
#             usage.cpu_cycles_start = usage.start_time_ns  # Approximation
#             usage.memory_kb = self._get_tid_memory_kb(tid)
#             usage.is_complete = 0
#             usage.system_overhead_ns = 0  # Will be calculated in complete_resource_tracking
#             usage.thread_lifetime_ns = 0   # Will be calculated in complete_resource_tracking
            
#             # Store first SSL arrival time for overhead calculation (store in request buffer)
#             # We'll pass it to complete_resource_tracking
            
#             # Use struct key for resource map
#             req_key = resource_map.Key()
#             req_key.id = request_id.encode('utf-8')[:63] + b'\x00'
#             resource_map[req_key] = usage
            
#         except Exception as e:
#             print(f"  [⚠] Error tracking resources: {e}")
    
#     def complete_resource_tracking(self, request_id, first_ssl_arrival_ns=None):
#         """Mark request as complete and calculate final metrics"""
#         try:
#             resource_map = self.bpf.get_table("request_resources")
#             thread_start_map = self.bpf.get_table("tid_to_thread_start")
            
#             # Create request ID key struct
#             req_key = resource_map.Key()
#             req_key.id = request_id.encode('utf-8')[:63] + b'\x00'
            
#             usage = resource_map[req_key]
#             completion_time_ns = int(time.time() * 1_000_000_000)
#             usage.end_time_ns = completion_time_ns
#             usage.cpu_cycles_end = usage.end_time_ns
#             usage.duration_ns = usage.end_time_ns - usage.start_time_ns
#             usage.cpu_cycles_used = usage.cpu_cycles_end - usage.cpu_cycles_start
            
#             # Calculate system overhead: accumulate from BPF per-TID overhead map
#             try:
#                 overhead_map = self.bpf.get_table("tid_to_overhead_ns")
#                 tid_key = overhead_map.Key(usage.tid)
#                 usage.system_overhead_ns = overhead_map[tid_key]
#             except Exception:
#                 # If not found, leave as 0
#                 pass
            
#             # Calculate thread lifetime: time from thread start (first recv/read) to thread exit
#             # Note: If thread has already exited, BPF probe has already set thread_lifetime_ns
#             # Otherwise, calculate partial lifetime (thread still running)
#             tid_key = thread_start_map.Key(usage.tid)
#             try:
#                 thread_start_ns = thread_start_map[tid_key]
#                 # Only update if not already set by BPF exit probe (thread_lifetime_ns == 0 means thread hasn't exited yet)
#                 if usage.thread_lifetime_ns == 0:
#                     # Thread still running, calculate partial lifetime
#                     usage.thread_lifetime_ns = completion_time_ns - thread_start_ns
#             except KeyError:
#                 # Thread start not tracked, use duration as estimate
#                 if usage.thread_lifetime_ns == 0:
#                     usage.thread_lifetime_ns = usage.duration_ns
            
#             # Refresh memory usage at completion
#             usage.memory_kb = max(usage.memory_kb, self._get_tid_memory_kb(usage.tid))
#             usage.is_complete = 1
            
#             resource_map[req_key] = usage
            
#             # Display resource usage
#             duration_ms = usage.duration_ns / 1_000_000.0
#             lifetime_ms = usage.thread_lifetime_ns / 1_000_000.0
            
#             # Check if thread has exited (if thread_start_map entry is gone, thread has exited)
#             thread_start_map = self.bpf.get_table("tid_to_thread_start")
#             tid_key = thread_start_map.Key(usage.tid)
#             thread_exited = False
#             try:
#                 # If we can't find the thread start, thread has likely exited
#                 _ = thread_start_map[tid_key]
#             except KeyError:
#                 thread_exited = True
            
#             lifetime_status = "(final)" if thread_exited else "(estimated, thread still running)"
            
#             print(f"  [⏱] Resource Usage for {request_id}:")
#             print(f"      Duration: {duration_ms:.2f} ms")
#             print(f"      CPU Cycles: {usage.cpu_cycles_used:,}")
#             if usage.memory_kb:
#                 print(f"      Memory: {usage.memory_kb} KB")
#             print(f"      System Overhead: {usage.system_overhead_ns:,} ns")
#             print(f"      Thread Lifetime: {lifetime_ms:.2f} ms {lifetime_status}")
            
#         except Exception as e:
#             pass  # Request might not be tracked

#     def _get_tid_memory_kb(self, tid):
#         """Return VmRSS (kB) for a given thread id by reading /proc."""
#         try:
#             pid = os.getpid()
#             status_path = f"/proc/{pid}/task/{tid}/status"
#             with open(status_path, 'r') as f:
#                 for line in f:
#                     if line.startswith('VmRSS:'):
#                         parts = line.split()
#                         if len(parts) >= 2:
#                             return int(parts[1])  # already in kB
#         except Exception:
#             return 0
#         return 0
    
#     def display_user_history(self, username, history):
#         """Display complete request history for a user"""
#         print("\n" + "╔" + "═" * 78 + "╗")
#         print(f"║ 👤 USER: {username:67} ║")
#         print("╠" + "═" * 78 + "╣")
        
#         count = history.request_count
#         print(f"║ Total Requests: {count:63} ║")
#         print("╠" + "═" * 78 + "╣")
        
#         if count == 0:
#             print("║ No requests yet" + " " * 62 + "║")
#         else:
#             print("║ #  │ Request ID          │   Time   │ Thread │ Source IP:Port     │ Overhead (ns) │ Thread Lifetime ║")
#             print("╠" + "═" * 78 + "╣")
            
#             # Access resource map to enrich rows with overhead and lifetime
#             resource_map = self.bpf.get_table("request_resources")
            
#             for i in range(min(count, 100)):
#                 req_entry = history.requests[i]
#                 req_id = req_entry.request_id.decode('utf-8', errors='ignore').rstrip('\x00')
                
#                 if not req_id:
#                     continue
                
#                 ts_sec = req_entry.timestamp_ns / 1_000_000_000
#                 time_str = time.strftime('%H:%M:%S', time.localtime(ts_sec))
#                 src_ip_str = self.ip_to_str(req_entry.src_ip)
                
#                 # Lookup resource usage by request id to fetch overhead and lifetime
#                 overhead_str = "-"
#                 lifetime_str = "-"
#                 try:
#                     req_key = resource_map.Key()
#                     req_key.id = req_id.encode('utf-8')[:63] + b'\x00'
#                     usage = resource_map[req_key]
#                     overhead_ns = usage.system_overhead_ns if usage.system_overhead_ns > 0 else 0
#                     lifetime_ms = usage.thread_lifetime_ns / 1_000_000.0 if usage.thread_lifetime_ns > 0 else 0.0
#                     overhead_str = f"{overhead_ns:,} ns" if overhead_ns > 0 else "0 ns"
#                     lifetime_str = f"{lifetime_ms:8.2f} ms" if lifetime_ms > 0 else "   -    "
#                 except Exception:
#                     pass
                
#                 print(f"║ {i+1:2} │ {req_id:19} │ {time_str:>8} │ {req_entry.tid:6} │ {src_ip_str:15}:{req_entry.src_port:5} │ {overhead_str:>14} │ {lifetime_str:>15} ║")
        
#         print("╚" + "═" * 78 + "╝\n")
    
#     def handle_ssl_event(self, cpu, data, size):
#         """Process SSL events"""
#         event = self.bpf["ssl_events"].event(data)
#         tid = event.tid
#         data_bytes = bytes(event.data[:event.data_len])
        
#         if tid not in self.request_buffers:
#             now_ns = int(time.time() * 1_000_000_000)
#             self.request_buffers[tid] = {
#                 'data': b'',
#                 'pid': event.pid,
#                 'tid': tid,
#                 'comm': event.comm.decode('utf-8', 'ignore'),
#                 'has_conn_info': event.has_conn_info,
#                 'src_ip': event.src_ip,
#                 'dst_ip': event.dst_ip,
#                 'src_port': event.src_port,
#                 'dst_port': event.dst_port,
#                 'timestamp': time.time(),
#                 'start_time': time.time(),
#                 'first_ssl_arrival_ns': now_ns  # Track when SSL data first arrives (for overhead calculation)
#             }
        
#         self.request_buffers[tid]['data'] += data_bytes
        
#         if event.has_conn_info:
#             self.request_buffers[tid]['has_conn_info'] = True
#             self.request_buffers[tid]['src_ip'] = event.src_ip
#             self.request_buffers[tid]['dst_ip'] = event.dst_ip
#             self.request_buffers[tid]['src_port'] = event.src_port
#             self.request_buffers[tid]['dst_port'] = event.dst_port
        
#         full_data = self.request_buffers[tid]['data']
#         if b'\r\n\r\n' in full_data or b'\n\n' in full_data:
#             if (full_data.startswith(b'GET') or full_data.startswith(b'POST') or
#                 full_data.startswith(b'PUT') or full_data.startswith(b'DELETE') or
#                 full_data.startswith(b'HEAD') or full_data.startswith(b'OPTIONS') or
#                 full_data.startswith(b'PATCH')):
                
#                 self.display_complete_request(tid)
            
#             del self.request_buffers[tid]
        
#         # Cleanup
#         now = time.time()
#         if now - self.last_cleanup > 5:
#             self.last_cleanup = now
#             expired = [t for t, req in self.request_buffers.items()
#                       if now - req['timestamp'] > 5]
#             for t in expired:
#                 del self.request_buffers[t]
    
#     def display_complete_request(self, tid):
#         """Display complete request with all tracking info"""
#         req = self.request_buffers[tid]
        
#         print("\n" + "=" * 80)
#         print("[HTTPS REQUEST INTERCEPTED]")
#         print("=" * 80)
#         print(f"Process ID (PID):        {req['pid']}")
#         print(f"Thread ID (TID):         {req['tid']}")
#         print(f"Process Name:            {req['comm']}")
        
#         # Connection info
#         if req['has_conn_info']:
#             src_ip = self.ip_to_str(req['src_ip'])
#             dst_ip = self.ip_to_str(req['dst_ip'])
#             print(f"\nConnection 4-tuple:")
#             print(f"  Source:      {src_ip}:{req['src_port']} (client)")
#             print(f"  Destination: {dst_ip}:{req['dst_port']} (server)")
#         else:
#             print(f"\nConnection Info: [Not available]")
        
#         # HTTP headers
#         headers = self.parse_http_headers(req['data'])
#         print(f"\nHTTP Request Headers:")
#         print("-" * 80)
#         print(headers)
#         print("-" * 80)
        
#         # Extract request ID
#         request_id = self.extract_request_id(headers)
#         print(f"\n📝 Request ID: {request_id}")
        
#         # Extract user info
#         user_info = self.extract_user_info(headers)
        
#         if user_info['has_username'] or user_info['has_cookie'] or user_info['has_authorization']:
#             print(f"\n👤 User Information:")
#             print("-" * 80)
#             if user_info['has_username']:
#                 print(f"  Username:      {user_info['username']}")
#             if user_info['has_cookie']:
#                 print(f"  Cookie:        {user_info['cookie']}")
#             if user_info['has_authorization']:
#                 print(f"  Authorization: {user_info['authorization']}")
#             print("-" * 80)
            
#             # Update tid_to_user_info map
#             self.update_user_info_map(tid, user_info)
            
#             # Update user request history
#             if user_info['has_username'] and req['has_conn_info']:
#                 self.update_user_history(
#                     user_info['username'],
#                     request_id,
#                     tid,
#                     req['src_ip'],
#                     req['src_port']
#                 )
        
#         # Resource tracking
#         first_ssl_arrival_ns = req.get('first_ssl_arrival_ns')
#         self.update_resource_tracking(request_id, tid, first_ssl_arrival_ns)
        
#         # Mark as complete
#         duration = time.time() - req['start_time']
#         print(f"\n⏱ Processing Time: {duration*1000:.2f} ms")
        
#         self.complete_resource_tracking(request_id, first_ssl_arrival_ns)
        
#         print()
    
#     def update_user_info_map(self, tid, user_info):
#         """Update tid_to_user_info BPF map"""
#         try:
#             user_info_map = self.bpf.get_table("tid_to_user_info")
#             info_struct = user_info_map.Leaf()
            
#             if user_info['has_username']:
#                 info_struct.username = user_info['username'].encode('utf-8')[:63] + b'\x00'
#                 info_struct.has_username = 1
            
#             if user_info['has_cookie']:
#                 info_struct.cookie = user_info['cookie'].encode('utf-8')[:255] + b'\x00'
#                 info_struct.has_cookie = 1
            
#             if user_info['has_authorization']:
#                 info_struct.authorization = user_info['authorization'].encode('utf-8')[:127] + b'\x00'
#                 info_struct.has_authorization = 1
            
#             tid_key = user_info_map.Key(tid)
#             user_info_map[tid_key] = info_struct
            
#         except Exception as e:
#             print(f"  [⚠] Could not update user info map: {e}")
    
#     def display_all_summaries(self):
#         """Display all tracking summaries on exit"""
#         self.display_resource_summary()
#         self.display_user_histories()
    
#     def display_resource_summary(self):
#         """Display resource usage summary"""
#         print("\n" + "=" * 80)
#         print("📊 RESOURCE USAGE SUMMARY")
#         print("=" * 80)
        
#         try:
#             resource_map = self.bpf.get_table("request_resources")
            
#             if len(resource_map) == 0:
#                 print("  No resource data tracked.")
#             else:
#                 print(f"  Total requests tracked: {len(resource_map)}\n")
#                 print(f"  {'Request ID':<20} │ {'Duration':<12} │ {'CPU Cycles':<15} │ {'Memory':<10} │ {'Overhead (ns)':<15} │ {'Thread Lifetime':<16} │ {'Status':<10}")
#                 print("  " + "-" * 130)
                
#                 for req_id_key, usage in resource_map.items():
#                     request_id = req_id_key.id.decode('utf-8', errors='ignore').rstrip('\x00')
#                     if not request_id:
#                         continue
                    
#                     duration_ms = usage.duration_ns / 1_000_000.0 if usage.duration_ns > 0 else 0
#                     overhead_ns = usage.system_overhead_ns if usage.system_overhead_ns > 0 else 0
#                     lifetime_ms = usage.thread_lifetime_ns / 1_000_000.0 if usage.thread_lifetime_ns > 0 else 0
#                     status = "Complete" if usage.is_complete else "In Progress"
#                     mem_str = f"{usage.memory_kb} KB" if usage.memory_kb else "-"
#                     overhead_str = f"{overhead_ns:,} ns" if overhead_ns > 0 else "0 ns"
                    
#                     print(f"  {request_id:<20} │ {duration_ms:>10.2f} ms │ {usage.cpu_cycles_used:>13,} │ {mem_str:>10} │ {overhead_str:>15} │ {lifetime_ms:>14.2f} ms │ {status:<10}")
#         except Exception as e:
#             print(f"  Error: {e}")
        
#         print("=" * 80)
    
#     def display_user_histories(self):
#         """Display all user request histories"""
#         print("\n" + "=" * 80)
#         print("👥 USER REQUEST HISTORIES")
#         print("=" * 80)
        
#         try:
#             user_history_map = self.bpf.get_table("user_request_history")
            
#             if len(user_history_map) == 0:
#                 print("  No user histories tracked.")
#             else:
#                 print(f"  Total users tracked: {len(user_history_map)}\n")
                
#                 for username_key, history in user_history_map.items():
#                     username = username_key.name.decode('utf-8', errors='ignore').rstrip('\x00')
#                     if username:
#                         self.display_user_history(username, history)
#         except Exception as e:
#             print(f"  Error: {e}")
        
#         print("=" * 80)
    
#     def run(self):
#         """Main execution"""
#         print("=" * 80)
#         print("🔍 Integrated HTTPS Server Sniffer")
#         print("=" * 80)
#         print("Features:")
#         print("  ✓ Connection attribution (TID → FD → Connection)")
#         print("  ✓ User information extraction")
#         print("  ✓ Resource usage tracking per request")
#         print("  ✓ User request history tracking")
#         print("=" * 80)
#         print("\nInitializing eBPF probes...\n")
        
#         try:
#             self.bpf = BPF(text=BPF_PROGRAM)
            
#             ssl_lib = "/usr/lib/libssl.so.3"
            
#             try:
#                 self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read",
#                                       fn_name="probe_ssl_read_enter")
#                 self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read",
#                                          fn_name="probe_ssl_read_exit")
#                 print(f"✓ Attached to SSL_read")
#             except Exception as e:
#                 print(f"⚠ Could not attach to SSL_read: {e}")
            
#             try:
#                 self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read_ex",
#                                       fn_name="probe_ssl_read_ex_enter")
#                 self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read_ex",
#                                          fn_name="probe_ssl_read_ex_exit")
#                 print(f"✓ Attached to SSL_read_ex")
#             except Exception as e:
#                 print(f"⚠ Could not attach to SSL_read_ex: {e}")
            
#             print("\n" + "=" * 80)
#             print("🎯 Monitoring HTTPS traffic...")
#             print("   All features active: connection, user info, resources, history")
#             print("=" * 80)
#             print()
            
#             self.bpf["ssl_events"].open_perf_buffer(self.handle_ssl_event)
            
#             while True:
#                 try:
#                     self.bpf.perf_buffer_poll(timeout=100)
#                 except KeyboardInterrupt:
#                     print("\n\n🛑 Stopping sniffer...")
#                     self.display_all_summaries()
#                     break
                    
#         except Exception as e:
#             print(f"Error: {e}")
#             import traceback
#             traceback.print_exc()


# if __name__ == "__main__":
#     import os
    
#     if os.geteuid() != 0:
#         print("This program must be run as root!")
#         print("Usage: sudo python3 integrated_sniffer.py")
#         exit(1)
    
#     sniffer = IntegratedSniffer()
#     sniffer.run()

#!/usr/bin/env python3
# """
# Integrated HTTPS Server Sniffer
# ================================
# Combines all tracking features:
# 1. Connection attribution (TID → FD → Connection)
# 2. User information extraction (username, cookie, authorization)
# 3. Resource usage tracking (CPU, memory, time per request)
# 4. User request history (all requests per user)

# Usage: sudo python3 integrated_sniffer.py
# """

# from bcc import BPF
# import socket
# import struct
# import ctypes
# import time
# import re
# import os

# # Combined eBPF Program
# BPF_PROGRAM = """
# #include <uapi/linux/ptrace.h>
# #include <net/sock.h>
# #include <net/inet_sock.h>
# #include <linux/sched.h>
# #include <linux/fdtable.h>
# #include <linux/fs.h>
# #include <linux/socket.h>
# #include <linux/net.h>

# #define MAX_HEADER_SIZE 1024
# #define MAX_USERNAME_LEN 64
# #define MAX_COOKIE_LEN 256
# #define MAX_AUTH_LEN 128
# #define MAX_REQUEST_ID_LEN 64
# #define MAX_REQUESTS_PER_USER 100

# // ═══════════════════════════════════════════════════════════════
# // DATA STRUCTURES
# // ═══════════════════════════════════════════════════════════════

# // Connection 4-tuple
# struct conn_tuple_t {
#     u32 src_ip;
#     u32 dst_ip;
#     u16 src_port;
#     u16 dst_port;
# };

# // Key structures (struct wrappers for arrays)
# struct request_id_key_t {
#     char id[MAX_REQUEST_ID_LEN];
# };

# struct username_key_t {
#     char name[MAX_USERNAME_LEN];
# };

# // User information from HTTP headers
# struct user_info_t {
#     char username[MAX_USERNAME_LEN];
#     char cookie[MAX_COOKIE_LEN];
#     char authorization[MAX_AUTH_LEN];
#     u8 has_username;
#     u8 has_cookie;
#     u8 has_authorization;
# };

# // Resource usage per request
# struct resource_usage_t {
#     char request_id[MAX_REQUEST_ID_LEN];
#     u32 tid;
#     u64 start_time_ns;
#     u64 end_time_ns;
#     u64 duration_ns;
#     u64 cpu_cycles_start;
#     u64 cpu_cycles_end;
#     u64 cpu_cycles_used;
#     u32 memory_kb;            // Resident memory (approx., userspace filled)
#     u64 system_overhead_ns;    // Time spent in our eBPF/userspace tracking
#     u64 thread_lifetime_ns;    // Estimated lifetime of thread processing this request
#     u8 is_complete;
# };

# // Single request entry in user history
# struct request_entry_t {
#     char request_id[MAX_REQUEST_ID_LEN];
#     u64 timestamp_ns;
#     u32 tid;
#     u32 src_ip;
#     u16 src_port;
# };

# // User request history
# struct user_history_t {
#     char username[MAX_USERNAME_LEN];
#     struct request_entry_t requests[MAX_REQUESTS_PER_USER];
#     u32 request_count;
#     u64 last_updated_ns;
# };

# // Event sent to userspace
# struct ssl_data_event_t {
#     u32 pid;
#     u32 tid;
#     char comm[TASK_COMM_LEN];
#     u32 src_ip;
#     u32 dst_ip;
#     u16 src_port;
#     u16 dst_port;
#     u32 data_len;
#     char data[MAX_HEADER_SIZE];
#     u8 has_conn_info;
# };

# // ═══════════════════════════════════════════════════════════════
# // PRIMARY MAPS
# // ═══════════════════════════════════════════════════════════════

# // 1. Connection attribution
# BPF_HASH(fd_to_conn, u32, struct conn_tuple_t);
# BPF_HASH(tid_to_fd, u64, u32);

# // 2. User information
# BPF_HASH(tid_to_user_info, u32, struct user_info_t);

# // 3. Resource tracking
# BPF_HASH(request_resources, struct request_id_key_t, struct resource_usage_t);
# BPF_HASH(tid_to_request_id, u32, struct request_id_key_t);
# BPF_HASH(tid_to_thread_start, u32, u64);  // Track when thread first starts processing (first recv/read)
# // Per-TID cumulative overhead incurred by our probes (in ns)
# BPF_HASH(tid_to_overhead_ns, u32, u64);

# // 4. User request history
# BPF_HASH(user_request_history, struct username_key_t, struct user_history_t);

# // Output channel
# BPF_PERF_OUTPUT(ssl_events);

# // Temporary storage
# BPF_HASH(ssl_read_args, u64, void *);
# BPF_PERCPU_ARRAY(event_scratch, struct ssl_data_event_t, 1);

# // ═══════════════════════════════════════════════════════════════
# // HELPER: Get socket from FD
# // ═══════════════════════════════════════════════════════════════

# static struct sock* get_sock_from_fd(u32 fd) {
#     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
#     struct files_struct *files = task->files;
#     if (files == NULL) return NULL;
    
#     struct fdtable *fdt = files->fdt;
#     if (fdt == NULL) return NULL;
    
#     if (fd >= fdt->max_fds) return NULL;
    
#     struct file **fd_array;
#     bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    
#     struct file *file;
#     bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
#     if (file == NULL) return NULL;
    
#     struct socket *sock_obj;
#     bpf_probe_read_kernel(&sock_obj, sizeof(sock_obj), &file->private_data);
#     if (sock_obj == NULL) return NULL;
    
#     struct sock *sk;
#     bpf_probe_read_kernel(&sk, sizeof(sk), &sock_obj->sk);
    
#     return sk;
# }

# // ═══════════════════════════════════════════════════════════════
# // CONNECTION TRACKING: First recv() establishes FD→Connection
# // ═══════════════════════════════════════════════════════════════

# TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 fd = (u32)args->fd;
#     u64 t0 = bpf_ktime_get_ns();
    
#     // ALWAYS recompute connection tuple for this FD to avoid stale cache
#     struct sock *sk = get_sock_from_fd(fd);
#     if (sk == NULL) return 0;
    
#     u16 family;
#     bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
#     if (family != AF_INET) return 0;
    
#     struct conn_tuple_t conn = {};
#     // Prefer inet_sock fields for reliability across kernels
#     struct inet_sock *inet = (struct inet_sock *)sk;
#     u16 sport_be = 0, dport_be = 0;
#     bpf_probe_read_kernel(&conn.src_ip, sizeof(u32), &inet->inet_daddr);      // client IP
#     bpf_probe_read_kernel(&conn.dst_ip, sizeof(u32), &inet->inet_rcv_saddr);  // server IP
#     bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);         // local/server port
#     bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);         // remote/client port
#     conn.src_port = bpf_ntohs(dport_be);  // client port
#     conn.dst_port = bpf_ntohs(sport_be);  // server port
    
#     // Update cache on every recv/read; FD numbers can be reused
#     fd_to_conn.update(&fd, &conn);
#     tid_to_fd.update(&pid_tgid, &fd);
    
#     // Track thread start time (first time we see this TID processing)
#     u32 tid = (u32)pid_tgid;
#     u64 *existing_start = tid_to_thread_start.lookup(&tid);
#     if (existing_start == NULL) {
#         u64 start_time = bpf_ktime_get_ns();
#         tid_to_thread_start.update(&tid, &start_time);
#     }
    
#     // Accumulate probe overhead for this TID
#     u32 tid_acc = (u32)pid_tgid;
#     u64 t1 = bpf_ktime_get_ns();
#     u64 delta = t1 - t0;
#     u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
#     if (acc_ptr) {
#         u64 acc = *acc_ptr + delta;
#         tid_to_overhead_ns.update(&tid_acc, &acc);
#     } else {
#         tid_to_overhead_ns.update(&tid_acc, &delta);
#     }
#     return 0;
# }

# TRACEPOINT_PROBE(syscalls, sys_enter_read) {
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 fd = (u32)args->fd;
#     u64 t0 = bpf_ktime_get_ns();
    
#     // ALWAYS recompute connection tuple for this FD to avoid stale cache
#     struct sock *sk = get_sock_from_fd(fd);
#     if (sk == NULL) return 0;
    
#     u16 family;
#     bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
#     if (family != AF_INET) return 0;
    
#     struct conn_tuple_t conn = {};
#     struct inet_sock *inet = (struct inet_sock *)sk;
#     u16 sport_be = 0, dport_be = 0;
#     bpf_probe_read_kernel(&conn.src_ip, sizeof(u32), &inet->inet_daddr);
#     bpf_probe_read_kernel(&conn.dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
#     bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
#     bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
#     conn.src_port = bpf_ntohs(dport_be);
#     conn.dst_port = bpf_ntohs(sport_be);
    
#     fd_to_conn.update(&fd, &conn);
#     tid_to_fd.update(&pid_tgid, &fd);
    
#     // Track thread start time (first time we see this TID processing)
#     u32 tid = (u32)pid_tgid;
#     u64 *existing_start = tid_to_thread_start.lookup(&tid);
#     if (existing_start == NULL) {
#         u64 start_time = bpf_ktime_get_ns();
#         tid_to_thread_start.update(&tid, &start_time);
#     }
    
#     // Accumulate probe overhead for this TID
#     u32 tid_acc = (u32)pid_tgid;
#     u64 t1 = bpf_ktime_get_ns();
#     u64 delta = t1 - t0;
#     u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
#     if (acc_ptr) {
#         u64 acc = *acc_ptr + delta;
#         tid_to_overhead_ns.update(&tid_acc, &acc);
#     } else {
#         tid_to_overhead_ns.update(&tid_acc, &delta);
#     }
#     return 0;
# }

# // ═══════════════════════════════════════════════════════════════
# // SSL INTERCEPTION
# // ═══════════════════════════════════════════════════════════════

# int probe_ssl_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     ssl_read_args.update(&pid_tgid, &buf);
#     return 0;
# }

# int probe_ssl_read_exit(struct pt_regs *ctx) {
#     u64 t0 = bpf_ktime_get_ns();
#     int ret = PT_REGS_RC(ctx);
#     if (ret <= 0) return 0;
    
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 pid = pid_tgid >> 32;
#     u32 tid = (u32)pid_tgid;
    
#     void **buf_ptr = ssl_read_args.lookup(&pid_tgid);
#     if (buf_ptr == NULL) return 0;
#     void *buf = *buf_ptr;
#     ssl_read_args.delete(&pid_tgid);
    
#     u32 zero = 0;
#     struct ssl_data_event_t *evt = event_scratch.lookup(&zero);
#     if (evt == NULL) return 0;
    
#     evt->pid = pid;
#     evt->tid = tid;
#     evt->has_conn_info = 0;
#     evt->src_ip = 0;
#     evt->dst_ip = 0;
#     evt->src_port = 0;
#     evt->dst_port = 0;
    
#     bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
#     u32 copy_len = (u32)ret;
#     if (copy_len > MAX_HEADER_SIZE) copy_len = MAX_HEADER_SIZE;
#     bpf_probe_read_user(&evt->data, copy_len, buf);
#     evt->data_len = copy_len;
    
#     // Resolve connection on EVERY SSL read using current FD
#     u32 *fd_ptr = tid_to_fd.lookup(&pid_tgid);
#     if (fd_ptr != NULL) {
#         u32 fd = *fd_ptr;
#         struct sock *sk = get_sock_from_fd(fd);
#         if (sk != NULL) {
#             u16 family;
#             bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
#             if (family == AF_INET) {
#                 struct inet_sock *inet = (struct inet_sock *)sk;
#                 u16 sport_be = 0, dport_be = 0;
#                 bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_daddr);
#                 bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
#                 bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
#                 bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
#                 evt->src_port = bpf_ntohs(dport_be);
#                 evt->dst_port = bpf_ntohs(sport_be);
#                 evt->has_conn_info = 1;
#             }
#         }
#     }
    
#     ssl_events.perf_submit(ctx, evt, sizeof(*evt));

#     // Accumulate probe overhead for this TID
#     u32 tid_acc = (u32)pid_tgid;
#     u64 t1 = bpf_ktime_get_ns();
#     u64 delta = t1 - t0;
#     u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
#     if (acc_ptr) {
#         u64 acc = *acc_ptr + delta;
#         tid_to_overhead_ns.update(&tid_acc, &acc);
#     } else {
#         tid_to_overhead_ns.update(&tid_acc, &delta);
#     }
#     return 0;
# }

# // SSL_read_ex support
# struct ssl_read_ex_args_t {
#     void *buf;
#     void *readbytes_ptr;
# };

# BPF_HASH(ssl_read_ex_args, u64, struct ssl_read_ex_args_t);

# int probe_ssl_read_ex_enter(struct pt_regs *ctx, void *ssl, void *buf,
#                              unsigned long num, void *readbytes) {
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     struct ssl_read_ex_args_t args = {.buf = buf, .readbytes_ptr = readbytes};
#     ssl_read_ex_args.update(&pid_tgid, &args);
#     return 0;
# }

# int probe_ssl_read_ex_exit(struct pt_regs *ctx) {
#     u64 t0 = bpf_ktime_get_ns();
#     int ret = PT_REGS_RC(ctx);
#     if (ret != 1) return 0;
    
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 pid = pid_tgid >> 32;
#     u32 tid = (u32)pid_tgid;
    
#     struct ssl_read_ex_args_t *args = ssl_read_ex_args.lookup(&pid_tgid);
#     if (args == NULL) return 0;
    
#     unsigned long bytes_read = 0;
#     bpf_probe_read_user(&bytes_read, sizeof(bytes_read), args->readbytes_ptr);
#     if (bytes_read <= 0) {
#         ssl_read_ex_args.delete(&pid_tgid);
#         return 0;
#     }
    
#     void *buf = args->buf;
#     ssl_read_ex_args.delete(&pid_tgid);
    
#     u32 zero = 0;
#     struct ssl_data_event_t *evt = event_scratch.lookup(&zero);
#     if (evt == NULL) return 0;
    
#     evt->pid = pid;
#     evt->tid = tid;
#     evt->has_conn_info = 0;
#     evt->src_ip = 0;
#     evt->dst_ip = 0;
#     evt->src_port = 0;
#     evt->dst_port = 0;
    
#     bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
#     u32 copy_len = (u32)bytes_read;
#     if (copy_len > MAX_HEADER_SIZE) copy_len = MAX_HEADER_SIZE;
#     bpf_probe_read_user(&evt->data, copy_len, buf);
#     evt->data_len = copy_len;
    
#     u32 *fd_ptr = tid_to_fd.lookup(&pid_tgid);
#     if (fd_ptr != NULL) {
#         u32 fd = *fd_ptr;
#         struct sock *sk = get_sock_from_fd(fd);
#         if (sk != NULL) {
#             u16 family;
#             bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
#             if (family == AF_INET) {
#                 struct inet_sock *inet = (struct inet_sock *)sk;
#                 u16 sport_be = 0, dport_be = 0;
#                 bpf_probe_read_kernel(&evt->src_ip, sizeof(u32), &inet->inet_daddr);
#                 bpf_probe_read_kernel(&evt->dst_ip, sizeof(u32), &inet->inet_rcv_saddr);
#                 bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);
#                 bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);
#                 evt->src_port = bpf_ntohs(dport_be);
#                 evt->dst_port = bpf_ntohs(sport_be);
#                 evt->has_conn_info = 1;
#             }
#         }
#     }
    
#     ssl_events.perf_submit(ctx, evt, sizeof(*evt));

#     // Accumulate probe overhead for this TID
#     u32 tid_acc = (u32)pid_tgid;
#     u64 t1 = bpf_ktime_get_ns();
#     u64 delta = t1 - t0;
#     u64 *acc_ptr = tid_to_overhead_ns.lookup(&tid_acc);
#     if (acc_ptr) {
#         u64 acc = *acc_ptr + delta;
#         tid_to_overhead_ns.update(&tid_acc, &acc);
#     } else {
#         tid_to_overhead_ns.update(&tid_acc, &delta);
#     }
#     return 0;
# }

# // ═══════════════════════════════════════════════════════════════
# // THREAD EXIT TRACKING: Update thread lifetime when thread exits
# // ═══════════════════════════════════════════════════════════════

# TRACEPOINT_PROBE(sched, sched_process_exit) {
#     // This fires when a process/thread exits
#     // Get the TID (in Linux, threads are processes, so this works for threads too)
#     u64 pid_tgid = bpf_get_current_pid_tgid();
#     u32 tid = (u32)pid_tgid;
    
#     // Look up thread start time
#     u64 *thread_start_ns = tid_to_thread_start.lookup(&tid);
#     if (thread_start_ns == NULL) return 0;  // Not a thread we're tracking
    
#     // Get current time (when thread is exiting)
#     u64 exit_time_ns = bpf_ktime_get_ns();
    
#     // Calculate final thread lifetime
#     u64 lifetime_ns = exit_time_ns - *thread_start_ns;
    
#     // Find the request associated with this TID
#     struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
#     if (req_id_key != NULL) {
#         // Update the resource_usage entry with final thread lifetime
#         struct resource_usage_t *usage = request_resources.lookup(req_id_key);
#         if (usage != NULL) {
#             // Update with final thread lifetime (thread has now exited)
#             usage->thread_lifetime_ns = lifetime_ns;
#             // Note: is_complete is managed by userspace resource tracking, not here
#         }
#     }
    
#     // Clean up thread tracking maps
#     tid_to_thread_start.delete(&tid);
#     tid_to_fd.delete(&pid_tgid);
#     tid_to_overhead_ns.delete(&tid);
    
#     return 0;
# }
# """

# class IntegratedSniffer:
#     def __init__(self):
#         self.bpf = None
#         self.request_buffers = {}
#         self.last_cleanup = 0
#         self.request_counter = 0
    
#     def ip_to_str(self, ip):
#         """Convert IPv4 from u32 to dotted-quad string (handles endianness)."""
#         try:
#             # Many kernels deliver sk addresses read into u32 that appear in host
#             # order on little-endian machines. Use little-endian packing which
#             # renders 127.0.0.1 correctly when the raw value is 0x0100007f.
#             return socket.inet_ntoa(struct.pack("<I", ip))
#         except Exception:
#             return "0.0.0.0"
    
#     def parse_http_headers(self, data):
#         """Parse HTTP headers"""
#         try:
#             text = data.decode('utf-8', errors='ignore')
#             header_end = text.find('\r\n\r\n')
#             if header_end == -1:
#                 header_end = text.find('\n\n')
#                 if header_end == -1:
#                     header_end = len(text)
#             return text[:header_end]
#         except:
#             return ""
    
#     def extract_request_id(self, headers_text):
#         """Extract or generate request ID"""
#         # Try to find X-Request-ID header
#         for line in headers_text.split('\n'):
#             line = line.strip()
#             if line.lower().startswith('x-request-id:'):
#                 return line[13:].strip()[:63]
        
#         # Try to extract from query params (e.g., ?id=REQ001)
#         first_line = headers_text.split('\n')[0] if headers_text else ""
#         match = re.search(r'[?&]id=([^&\s]+)', first_line)
#         if match:
#             return match.group(1)[:63]
        
#         # Generate unique ID
#         self.request_counter += 1
#         return f"AUTO_{self.request_counter:06d}"
    
#     def extract_user_info(self, headers_text):
#         """Extract username, cookie, and authorization from headers"""
#         user_info = {
#             'username': '',
#             'cookie': '',
#             'authorization': '',
#             'has_username': False,
#             'has_cookie': False,
#             'has_authorization': False
#         }
        
#         try:
#             for line in headers_text.split('\n'):
#                 line = line.strip()
                
#                 if line.lower().startswith('cookie:'):
#                     cookie_value = line[7:].strip()
#                     user_info['cookie'] = cookie_value[:255]
#                     user_info['has_cookie'] = True
                    
#                     # Extract username from cookie
#                     for part in cookie_value.split(';'):
#                         part = part.strip()
#                         if '=' in part:
#                             key, val = part.split('=', 1)
#                             if key.lower() in ['user', 'username', 'user_id']:
#                                 user_info['username'] = val[:63]
#                                 user_info['has_username'] = True
#                                 break
                
#                 elif line.lower().startswith('authorization:'):
#                     auth_value = line[14:].strip()
#                     user_info['authorization'] = auth_value[:127]
#                     user_info['has_authorization'] = True
                    
#                     if auth_value.lower().startswith('basic '):
#                         try:
#                             import base64
#                             encoded = auth_value[6:]
#                             decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
#                             if ':' in decoded:
#                                 username = decoded.split(':')[0]
#                                 user_info['username'] = username[:63]
#                                 user_info['has_username'] = True
#                         except:
#                             pass
                
#                 elif not user_info['has_username']:
#                     if line.lower().startswith('x-user:') or line.lower().startswith('x-username:'):
#                         colon_pos = line.find(':')
#                         if colon_pos > 0:
#                             username = line[colon_pos+1:].strip()
#                             user_info['username'] = username[:63]
#                             user_info['has_username'] = True
#         except:
#             pass
        
#         return user_info
    
#     def update_user_history(self, username, request_id, tid, src_ip, src_port):
#         """Add request to user's history and display"""
#         if not username:
#             return
        
#         try:
#             user_history_map = self.bpf.get_table("user_request_history")
            
#             # Create username key struct
#             username_key = user_history_map.Key()
#             username_key.name = username.encode('utf-8')[:63] + b'\x00'
            
#             try:
#                 history = user_history_map[username_key]
#                 request_count = history.request_count
#             except KeyError:
#                 history = user_history_map.Leaf()
#                 history.username = username.encode('utf-8')[:63] + b'\x00'
#                 history.request_count = 0
#                 request_count = 0
            
#             idx = request_count
#             if idx >= 100:
#                 # Shift array
#                 for i in range(99):
#                     history.requests[i] = history.requests[i + 1]
#                 idx = 99
#             else:
#                 history.request_count += 1
            
#             # Add new request
#             history.requests[idx].request_id = request_id.encode('utf-8')[:63] + b'\x00'
#             history.requests[idx].timestamp_ns = int(time.time() * 1_000_000_000)
#             history.requests[idx].tid = tid
#             history.requests[idx].src_ip = src_ip
#             history.requests[idx].src_port = src_port
#             history.last_updated_ns = int(time.time() * 1_000_000_000)
            
#             user_history_map[username_key] = history
            
#             # Display updated history
#             self.display_user_history(username, history)
            
#         except Exception as e:
#             print(f"  [⚠] Error updating user history: {e}")
    
#     def update_resource_tracking(self, request_id, tid, first_ssl_arrival_ns=None):
#         """Track resource usage for this request"""
#         try:
#             tid_to_req_map = self.bpf.get_table("tid_to_request_id")
#             resource_map = self.bpf.get_table("request_resources")
            
#             # Create request ID key struct
#             req_id_key = tid_to_req_map.Leaf()
#             req_id_key.id = request_id.encode('utf-8')[:63] + b'\x00'
            
#             # Store TID → Request ID
#             tid_key = tid_to_req_map.Key(tid)
#             tid_to_req_map[tid_key] = req_id_key
            
#             # Initialize resource tracking
#             usage = resource_map.Leaf()
#             usage.request_id = request_id.encode('utf-8')[:63] + b'\x00'
#             usage.tid = tid
#             usage.start_time_ns = int(time.time() * 1_000_000_000)
#             usage.cpu_cycles_start = usage.start_time_ns  # Approximation
#             usage.memory_kb = self._get_tid_memory_kb(tid)
#             usage.is_complete = 0
#             usage.system_overhead_ns = 0
#             usage.thread_lifetime_ns = 0
            
#             # Use struct key for resource map
#             req_key = resource_map.Key()
#             req_key.id = request_id.encode('utf-8')[:63] + b'\x00'
#             resource_map[req_key] = usage
            
#         except Exception as e:
#             print(f"  [⚠] Error tracking resources: {e}")
    
#     def complete_resource_tracking(self, request_id, first_ssl_arrival_ns=None):
#         """Mark request as complete and calculate final metrics"""
#         try:
#             resource_map = self.bpf.get_table("request_resources")
            
#             # Create request ID key struct
#             req_key = resource_map.Key()
#             req_key.id = request_id.encode('utf-8')[:63] + b'\x00'
            
#             usage = resource_map[req_key]
#             completion_time_ns = int(time.time() * 1_000_000_000)
#             usage.end_time_ns = completion_time_ns
#             usage.cpu_cycles_end = usage.end_time_ns
#             usage.duration_ns = usage.end_time_ns - usage.start_time_ns
#             usage.cpu_cycles_used = usage.cpu_cycles_end - usage.cpu_cycles_start
            
#             # ===================================================================
#             # MODIFIED: Store processing time in the overhead and lifetime fields
#             # ===================================================================
#             usage.system_overhead_ns = usage.duration_ns
#             usage.thread_lifetime_ns = usage.duration_ns
            
#             # Refresh memory usage at completion
#             usage.memory_kb = max(usage.memory_kb, self._get_tid_memory_kb(usage.tid))
#             usage.is_complete = 1
            
#             resource_map[req_key] = usage
            
#             # Display resource usage
#             duration_ms = usage.duration_ns / 1_000_000.0
#             lifetime_ms = usage.thread_lifetime_ns / 1_000_000.0
            
#             print(f"  [⏱] Resource Usage for {request_id}:")
#             print(f"      Duration: {duration_ms:.2f} ms")
#             print(f"      CPU Cycles: {usage.cpu_cycles_used:,}")
#             if usage.memory_kb:
#                 print(f"      Memory: {usage.memory_kb} KB")
#             # This now prints the processing time, as requested
#             print(f"      Proc. Time (from lifetime field): {lifetime_ms:.2f} ms")
            
#         except Exception as e:
#             pass  # Request might not be tracked

#     def _get_tid_memory_kb(self, tid):
#         """Return VmRSS (kB) for a given thread id by reading /proc."""
#         try:
#             pid = os.getpid()
#             status_path = f"/proc/{pid}/task/{tid}/status"
#             with open(status_path, 'r') as f:
#                 for line in f:
#                     if line.startswith('VmRSS:'):
#                         parts = line.split()
#                         if len(parts) >= 2:
#                             return int(parts[1])  # already in kB
#         except Exception:
#             return 0
#         return 0
    
#     def display_user_history(self, username, history):
#         """Display complete request history for a user"""
#         print("\n" + "╔" + "═" * 78 + "╗")
#         print(f"║ 👤 USER: {username:67} ║")
#         print("╠" + "═" * 78 + "╣")
        
#         count = history.request_count
#         print(f"║ Total Requests: {count:63} ║")
#         print("╠" + "═" * 78 + "╣")
        
#         if count == 0:
#             print("║ No requests yet" + " " * 62 + "║")
#         else:
#             # ====================================================
#             # MODIFIED: Update table header for processing time
#             # ====================================================
#             print("║ #  │ Request ID          │   Time   │ Thread │ Source IP:Port     │ Proc. Time (ms) │ Proc. Time (ms) ║")
#             print("╠" + "═" * 78 + "╣")
            
#             resource_map = self.bpf.get_table("request_resources")
            
#             for i in range(min(count, 100)):
#                 req_entry = history.requests[i]
#                 req_id = req_entry.request_id.decode('utf-8', errors='ignore').rstrip('\x00')
                
#                 if not req_id:
#                     continue
                
#                 ts_sec = req_entry.timestamp_ns / 1_000_000_000
#                 time_str = time.strftime('%H:%M:%S', time.localtime(ts_sec))
#                 src_ip_str = self.ip_to_str(req_entry.src_ip)
                
#                 # ==========================================================
#                 # MODIFIED: Display processing time in the last two columns
#                 # ==========================================================
#                 proc_time_str_1 = "-".center(14)
#                 proc_time_str_2 = "-".center(15)
#                 try:
#                     req_key = resource_map.Key()
#                     req_key.id = req_id.encode('utf-8')[:63] + b'\x00'
#                     usage = resource_map[req_key]
                    
#                     # Both fields now hold the duration. We read from them and format as ms.
#                     proc_time_ms1 = usage.system_overhead_ns / 1_000_000.0 if usage.system_overhead_ns > 0 else 0.0
#                     proc_time_ms2 = usage.thread_lifetime_ns / 1_000_000.0 if usage.thread_lifetime_ns > 0 else 0.0

#                     if proc_time_ms1 > 0:
#                         proc_time_str_1 = f"{proc_time_ms1:.2f} ms".rjust(14)
#                     if proc_time_ms2 > 0:
#                         proc_time_str_2 = f"{proc_time_ms2:.2f} ms".rjust(15)
#                 except Exception:
#                     pass
                
#                 print(f"║ {i+1:2} │ {req_id:19} │ {time_str:>8} │ {req_entry.tid:6} │ {src_ip_str:15}:{req_entry.src_port:5} │ {proc_time_str_1} │ {proc_time_str_2} ║")
        
#         print("╚" + "═" * 78 + "╝\n")
    
#     def handle_ssl_event(self, cpu, data, size):
#         """Process SSL events"""
#         event = self.bpf["ssl_events"].event(data)
#         tid = event.tid
#         data_bytes = bytes(event.data[:event.data_len])
        
#         if tid not in self.request_buffers:
#             now_ns = int(time.time() * 1_000_000_000)
#             self.request_buffers[tid] = {
#                 'data': b'',
#                 'pid': event.pid,
#                 'tid': tid,
#                 'comm': event.comm.decode('utf-8', 'ignore'),
#                 'has_conn_info': event.has_conn_info,
#                 'src_ip': event.src_ip,
#                 'dst_ip': event.dst_ip,
#                 'src_port': event.src_port,
#                 'dst_port': event.dst_port,
#                 'timestamp': time.time(),
#                 'start_time': time.time(),
#                 'first_ssl_arrival_ns': now_ns
#             }
        
#         self.request_buffers[tid]['data'] += data_bytes
        
#         if event.has_conn_info:
#             self.request_buffers[tid]['has_conn_info'] = True
#             self.request_buffers[tid]['src_ip'] = event.src_ip
#             self.request_buffers[tid]['dst_ip'] = event.dst_ip
#             self.request_buffers[tid]['src_port'] = event.src_port
#             self.request_buffers[tid]['dst_port'] = event.dst_port
        
#         full_data = self.request_buffers[tid]['data']
#         if b'\r\n\r\n' in full_data or b'\n\n' in full_data:
#             if (full_data.startswith(b'GET') or full_data.startswith(b'POST') or
#                 full_data.startswith(b'PUT') or full_data.startswith(b'DELETE') or
#                 full_data.startswith(b'HEAD') or full_data.startswith(b'OPTIONS') or
#                 full_data.startswith(b'PATCH')):
                
#                 self.display_complete_request(tid)
            
#             del self.request_buffers[tid]
        
#         now = time.time()
#         if now - self.last_cleanup > 5:
#             self.last_cleanup = now
#             expired = [t for t, req in self.request_buffers.items()
#                       if now - req['timestamp'] > 5]
#             for t in expired:
#                 del self.request_buffers[t]
    
#     def display_complete_request(self, tid):
#         """Display complete request with all tracking info"""
#         req = self.request_buffers[tid]
        
#         print("\n" + "=" * 80)
#         print("[HTTPS REQUEST INTERCEPTED]")
#         print("=" * 80)
#         print(f"Process ID (PID):        {req['pid']}")
#         print(f"Thread ID (TID):         {req['tid']}")
#         print(f"Process Name:            {req['comm']}")
        
#         if req['has_conn_info']:
#             src_ip = self.ip_to_str(req['src_ip'])
#             dst_ip = self.ip_to_str(req['dst_ip'])
#             print(f"\nConnection 4-tuple:")
#             print(f"  Source:      {src_ip}:{req['src_port']} (client)")
#             print(f"  Destination: {dst_ip}:{req['dst_port']} (server)")
#         else:
#             print(f"\nConnection Info: [Not available]")
        
#         headers = self.parse_http_headers(req['data'])
#         print(f"\nHTTP Request Headers:")
#         print("-" * 80)
#         print(headers)
#         print("-" * 80)
        
#         request_id = self.extract_request_id(headers)
#         print(f"\n📝 Request ID: {request_id}")
        
#         user_info = self.extract_user_info(headers)
        
#         if user_info['has_username'] or user_info['has_cookie'] or user_info['has_authorization']:
#             print(f"\n👤 User Information:")
#             print("-" * 80)
#             if user_info['has_username']:
#                 print(f"  Username:      {user_info['username']}")
#             if user_info['has_cookie']:
#                 print(f"  Cookie:        {user_info['cookie']}")
#             if user_info['has_authorization']:
#                 print(f"  Authorization: {user_info['authorization']}")
#             print("-" * 80)
            
#             self.update_user_info_map(tid, user_info)
            
#             if user_info['has_username'] and req['has_conn_info']:
#                 self.update_user_history(
#                     user_info['username'],
#                     request_id,
#                     tid,
#                     req['src_ip'],
#                     req['src_port']
#                 )
        
#         first_ssl_arrival_ns = req.get('first_ssl_arrival_ns')
#         self.update_resource_tracking(request_id, tid, first_ssl_arrival_ns)
        
#         duration = time.time() - req['start_time']
#         print(f"\n⏱ Processing Time: {duration*1000:.2f} ms")
        
#         self.complete_resource_tracking(request_id, first_ssl_arrival_ns)
        
#         print()
    
#     def update_user_info_map(self, tid, user_info):
#         """Update tid_to_user_info BPF map"""
#         try:
#             user_info_map = self.bpf.get_table("tid_to_user_info")
#             info_struct = user_info_map.Leaf()
            
#             if user_info['has_username']:
#                 info_struct.username = user_info['username'].encode('utf-8')[:63] + b'\x00'
#                 info_struct.has_username = 1
            
#             if user_info['has_cookie']:
#                 info_struct.cookie = user_info['cookie'].encode('utf-8')[:255] + b'\x00'
#                 info_struct.has_cookie = 1
            
#             if user_info['has_authorization']:
#                 info_struct.authorization = user_info['authorization'].encode('utf-8')[:127] + b'\x00'
#                 info_struct.has_authorization = 1
            
#             tid_key = user_info_map.Key(tid)
#             user_info_map[tid_key] = info_struct
            
#         except Exception as e:
#             print(f"  [⚠] Could not update user info map: {e}")
    
#     def display_all_summaries(self):
#         """Display all tracking summaries on exit"""
#         self.display_resource_summary()
#         self.display_user_histories()
    
#     def display_resource_summary(self):
#         """Display resource usage summary"""
#         print("\n" + "=" * 80)
#         print("📊 RESOURCE USAGE SUMMARY")
#         print("=" * 80)
        
#         try:
#             resource_map = self.bpf.get_table("request_resources")
            
#             if len(resource_map) == 0:
#                 print("  No resource data tracked.")
#             else:
#                 print(f"  Total requests tracked: {len(resource_map)}\n")
#                 # ===============================================
#                 # MODIFIED: Update summary header
#                 # ===============================================
#                 print(f"  {'Request ID':<20} │ {'Duration':<12} │ {'CPU Cycles':<15} │ {'Memory':<10} │ {'Proc. Time (ms)':<16} │ {'Proc. Time (ms)':<16} │ {'Status':<10}")
#                 print("  " + "-" * 130)
                
#                 for req_id_key, usage in resource_map.items():
#                     request_id = req_id_key.id.decode('utf-8', errors='ignore').rstrip('\x00')
#                     if not request_id:
#                         continue
                    
#                     duration_ms = usage.duration_ns / 1_000_000.0 if usage.duration_ns > 0 else 0
#                     status = "Complete" if usage.is_complete else "In Progress"
#                     mem_str = f"{usage.memory_kb} KB" if usage.memory_kb else "-"

#                     # ===============================================
#                     # MODIFIED: Display processing time in summary
#                     # ===============================================
#                     proc_time1_ms = usage.system_overhead_ns / 1_000_000.0 if usage.system_overhead_ns > 0 else 0
#                     proc_time2_ms = usage.thread_lifetime_ns / 1_000_000.0 if usage.thread_lifetime_ns > 0 else 0
#                     proc_time_str1 = f"{proc_time1_ms:.2f} ms"
#                     proc_time_str2 = f"{proc_time2_ms:.2f} ms"

#                     print(f"  {request_id:<20} │ {duration_ms:>10.2f} ms │ {usage.cpu_cycles_used:>13,} │ {mem_str:>10} │ {proc_time_str1:>16} │ {proc_time_str2:>16} │ {status:<10}")
#         except Exception as e:
#             print(f"  Error: {e}")
        
#         print("=" * 80)
    
#     def display_user_histories(self):
#         """Display all user request histories"""
#         print("\n" + "=" * 80)
#         print("👥 USER REQUEST HISTORIES")
#         print("=" * 80)
        
#         try:
#             user_history_map = self.bpf.get_table("user_request_history")
            
#             if len(user_history_map) == 0:
#                 print("  No user histories tracked.")
#             else:
#                 print(f"  Total users tracked: {len(user_history_map)}\n")
                
#                 for username_key, history in user_history_map.items():
#                     username = username_key.name.decode('utf-8', errors='ignore').rstrip('\x00')
#                     if username:
#                         self.display_user_history(username, history)
#         except Exception as e:
#             print(f"  Error: {e}")
        
#         print("=" * 80)
    
#     def run(self):
#         """Main execution"""
#         print("=" * 80)
#         print("🔍 Integrated HTTPS Server Sniffer")
#         print("=" * 80)
#         print("Features:")
#         print("  ✓ Connection attribution (TID → FD → Connection)")
#         print("  ✓ User information extraction")
#         print("  ✓ Resource usage tracking per request")
#         print("  ✓ User request history tracking")
#         print("=" * 80)
#         print("\nInitializing eBPF probes...\n")
        
#         try:
#             self.bpf = BPF(text=BPF_PROGRAM)
            
#             ssl_lib = "/usr/lib/libssl.so.3"
            
#             try:
#                 self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read",
#                                       fn_name="probe_ssl_read_enter")
#                 self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read",
#                                          fn_name="probe_ssl_read_exit")
#                 print(f"✓ Attached to SSL_read")
#             except Exception as e:
#                 print(f"⚠ Could not attach to SSL_read: {e}")
            
#             try:
#                 self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read_ex",
#                                       fn_name="probe_ssl_read_ex_enter")
#                 self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read_ex",
#                                          fn_name="probe_ssl_read_ex_exit")
#                 print(f"✓ Attached to SSL_read_ex")
#             except Exception as e:
#                 print(f"⚠ Could not attach to SSL_read_ex: {e}")
            
#             print("\n" + "=" * 80)
#             print("🎯 Monitoring HTTPS traffic...")
#             print("   All features active: connection, user info, resources, history")
#             print("=" * 80)
#             print()
            
#             self.bpf["ssl_events"].open_perf_buffer(self.handle_ssl_event)
            
#             while True:
#                 try:
#                     self.bpf.perf_buffer_poll(timeout=100)
#                 except KeyboardInterrupt:
#                     print("\n\n🛑 Stopping sniffer...")
#                     self.display_all_summaries()
#                     break
                    
#         except Exception as e:
#             print(f"Error: {e}")
#             import traceback
#             traceback.print_exc()

# if __name__ == "__main__":
#     import os
    
#     if os.geteuid() != 0:
#         print("This program must be run as root!")
#         print("Usage: sudo python3 integrated_sniffer.py")
#         exit(1)
    
#     sniffer = IntegratedSniffer()
#     sniffer.run()


#!/usr/bin/env python3
"""
Integrated HTTPS Server Sniffer
================================
Combines all tracking features:
1. Connection attribution (TID → FD → Connection)
2. User information extraction (username, cookie, authorization)
3. Resource usage tracking (CPU, memory, time per request)
4. User request history (all requests per user)

Usage: sudo python3 integrated_sniffer.py
"""

from bcc import BPF
import socket
import struct
import ctypes
import time
import re
import os

# Combined eBPF Program (No changes needed here, included for completeness)
BPF_PROGRAM = """
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

// ═══════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ═══════════════════════════════════════════════════════════════

// Connection 4-tuple
struct conn_tuple_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

// Key structures (struct wrappers for arrays)
struct request_id_key_t {
    char id[MAX_REQUEST_ID_LEN];
};

struct username_key_t {
    char name[MAX_USERNAME_LEN];
};

// User information from HTTP headers
struct user_info_t {
    char username[MAX_USERNAME_LEN];
    char cookie[MAX_COOKIE_LEN];
    char authorization[MAX_AUTH_LEN];
    u8 has_username;
    u8 has_cookie;
    u8 has_authorization;
};

// Resource usage per request
struct resource_usage_t {
    char request_id[MAX_REQUEST_ID_LEN];
    u32 tid;
    u64 start_time_ns;
    u64 end_time_ns;
    u64 duration_ns;
    u64 cpu_cycles_start;
    u64 cpu_cycles_end;
    u64 cpu_cycles_used;
    u32 memory_kb;            // Resident memory (approx., userspace filled)
    u64 system_overhead_ns;    // Time spent in our eBPF/userspace tracking
    u64 thread_lifetime_ns;    // Estimated lifetime of thread processing this request
    u8 is_complete;
};

// Single request entry in user history
struct request_entry_t {
    char request_id[MAX_REQUEST_ID_LEN];
    u64 timestamp_ns;
    u32 tid;
    u32 src_ip;
    u16 src_port;
};

// User request history
struct user_history_t {
    char username[MAX_USERNAME_LEN];
    struct request_entry_t requests[MAX_REQUESTS_PER_USER];
    u32 request_count;
    u64 last_updated_ns;
};

// Event sent to userspace
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

// ═══════════════════════════════════════════════════════════════
// PRIMARY MAPS
// ═══════════════════════════════════════════════════════════════

// 1. Connection attribution
BPF_HASH(fd_to_conn, u32, struct conn_tuple_t);
BPF_HASH(tid_to_fd, u64, u32);

// 2. User information
BPF_HASH(tid_to_user_info, u32, struct user_info_t);

// 3. Resource tracking
BPF_HASH(request_resources, struct request_id_key_t, struct resource_usage_t);
BPF_HASH(tid_to_request_id, u32, struct request_id_key_t);
BPF_HASH(tid_to_thread_start, u32, u64);  // Track when thread first starts processing (first recv/read)
// Per-TID cumulative overhead incurred by our probes (in ns)
BPF_HASH(tid_to_overhead_ns, u32, u64);

// 4. User request history
BPF_HASH(user_request_history, struct username_key_t, struct user_history_t);

// Output channel
BPF_PERF_OUTPUT(ssl_events);

// Temporary storage
BPF_HASH(ssl_read_args, u64, void *);
BPF_PERCPU_ARRAY(event_scratch, struct ssl_data_event_t, 1);

// ═══════════════════════════════════════════════════════════════
// HELPER: Get socket from FD
// ═══════════════════════════════════════════════════════════════

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
// CONNECTION TRACKING: First recv() establishes FD→Connection
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;
    u64 t0 = bpf_ktime_get_ns();
    
    // ALWAYS recompute connection tuple for this FD to avoid stale cache
    struct sock *sk = get_sock_from_fd(fd);
    if (sk == NULL) return 0;
    
    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;
    
    struct conn_tuple_t conn = {};
    // Prefer inet_sock fields for reliability across kernels
    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 sport_be = 0, dport_be = 0;
    bpf_probe_read_kernel(&conn.src_ip, sizeof(u32), &inet->inet_daddr);      // client IP
    bpf_probe_read_kernel(&conn.dst_ip, sizeof(u32), &inet->inet_rcv_saddr);  // server IP
    bpf_probe_read_kernel(&sport_be, sizeof(u16), &inet->inet_sport);         // local/server port
    bpf_probe_read_kernel(&dport_be, sizeof(u16), &inet->inet_dport);         // remote/client port
    conn.src_port = bpf_ntohs(dport_be);  // client port
    conn.dst_port = bpf_ntohs(sport_be);  // server port
    
    // Update cache on every recv/read; FD numbers can be reused
    fd_to_conn.update(&fd, &conn);
    tid_to_fd.update(&pid_tgid, &fd);
    
    // Track thread start time (first time we see this TID processing)
    u32 tid = (u32)pid_tgid;
    u64 *existing_start = tid_to_thread_start.lookup(&tid);
    if (existing_start == NULL) {
        u64 start_time = bpf_ktime_get_ns();
        tid_to_thread_start.update(&tid, &start_time);
    }
    
    // Accumulate probe overhead for this TID
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

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;
    u64 t0 = bpf_ktime_get_ns();
    
    // ALWAYS recompute connection tuple for this FD to avoid stale cache
    struct sock *sk = get_sock_from_fd(fd);
    if (sk == NULL) return 0;
    
    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) return 0;
    
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
    
    // Track thread start time (first time we see this TID processing)
    u32 tid = (u32)pid_tgid;
    u64 *existing_start = tid_to_thread_start.lookup(&tid);
    if (existing_start == NULL) {
        u64 start_time = bpf_ktime_get_ns();
        tid_to_thread_start.update(&tid, &start_time);
    }
    
    // Accumulate probe overhead for this TID
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
// SSL INTERCEPTION
// ═══════════════════════════════════════════════════════════════

int probe_ssl_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
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
    evt->src_ip = 0;
    evt->dst_ip = 0;
    evt->src_port = 0;
    evt->dst_port = 0;
    
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    u32 copy_len = (u32)ret;
    if (copy_len > MAX_HEADER_SIZE) copy_len = MAX_HEADER_SIZE;
    bpf_probe_read_user(&evt->data, copy_len, buf);
    evt->data_len = copy_len;
    
    // Resolve connection on EVERY SSL read using current FD
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

    // Accumulate probe overhead for this TID
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

// SSL_read_ex support
struct ssl_read_ex_args_t {
    void *buf;
    void *readbytes_ptr;
};

BPF_HASH(ssl_read_ex_args, u64, struct ssl_read_ex_args_t);

int probe_ssl_read_ex_enter(struct pt_regs *ctx, void *ssl, void *buf,
                             unsigned long num, void *readbytes) {
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
    ssl_read_ex_args.delete(&pid_tgid);
    
    u32 zero = 0;
    struct ssl_data_event_t *evt = event_scratch.lookup(&zero);
    if (evt == NULL) return 0;
    
    evt->pid = pid;
    evt->tid = tid;
    evt->has_conn_info = 0;
    evt->src_ip = 0;
    evt->dst_ip = 0;
    evt->src_port = 0;
    evt->dst_port = 0;
    
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    u32 copy_len = (u32)bytes_read;
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

    // Accumulate probe overhead for this TID
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
// FORK TRACKING: Propagate request ID to child processes
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u32 parent_pid = args->parent_pid;
    u32 child_pid = args->child_pid;  // Using PID as TID since Linux threads are processes

    // Check if parent is tracking a request
    struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&parent_pid);
    if (req_id_key != NULL) {
        // Propagate request ID to child
        tid_to_request_id.update(&child_pid, req_id_key);

        // Initialize start time for child
        u64 start_time = bpf_ktime_get_ns();
        tid_to_thread_start.update(&child_pid, &start_time);
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// THREAD EXIT TRACKING: Update thread lifetime when thread exits
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(sched, sched_process_exit) {
    // This fires when a process/thread exits
    // Get the TID (in Linux, threads are processes, so this works for threads too)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    
    // Look up thread start time
    u64 *thread_start_ns = tid_to_thread_start.lookup(&tid);
    if (thread_start_ns == NULL) return 0;  // Not a thread we're tracking
    
    // Get current time (when thread is exiting)
    u64 exit_time_ns = bpf_ktime_get_ns();
    
    // Calculate final thread lifetime
    u64 lifetime_ns = exit_time_ns - *thread_start_ns;
    
    // Find the request associated with this TID
    struct request_id_key_t *req_id_key = tid_to_request_id.lookup(&tid);
    if (req_id_key != NULL) {
        // Update the resource_usage entry with final thread lifetime
        struct resource_usage_t *usage = request_resources.lookup(req_id_key);
        if (usage != NULL) {
            // Atomically add lifetime to total
            // This works for both main thread and children
            lock_xadd(&usage->thread_lifetime_ns, lifetime_ns);
        }
    }
    
    // Clean up thread tracking maps
    tid_to_thread_start.delete(&tid);
    tid_to_fd.delete(&pid_tgid);
    tid_to_overhead_ns.delete(&tid);
    
    return 0;
}
"""

class IntegratedSniffer:
    def __init__(self):
        self.bpf = None
        self.request_buffers = {}
        self.last_cleanup = 0
        self.request_counter = 0

    def ip_to_str(self, ip):
        """Convert IPv4 from u32 to dotted-quad string (handles endianness)."""
        try:
            return socket.inet_ntoa(struct.pack("<I", ip))
        except Exception:
            return "0.0.0.0"

    def parse_http_headers(self, data):
        """Parse HTTP headers"""
        try:
            text = data.decode('utf-8', errors='ignore')
            header_end = text.find('\r\n\r\n')
            if header_end == -1:
                header_end = text.find('\n\n')
                if header_end == -1:
                    header_end = len(text)
            return text[:header_end]
        except:
            return ""

    def extract_request_id(self, headers_text):
        """Extract or generate request ID"""
        for line in headers_text.split('\n'):
            line = line.strip()
            if line.lower().startswith('x-request-id:'):
                return line[13:].strip()[:63]
        
        first_line = headers_text.split('\n')[0] if headers_text else ""
        match = re.search(r'[?&]id=([^&\s]+)', first_line)
        if match:
            return match.group(1)[:63]
        
        self.request_counter += 1
        return f"AUTO_{self.request_counter:06d}"

    def extract_user_info(self, headers_text):
        """Extract username, cookie, and authorization from headers"""
        user_info = {
            'username': '', 'cookie': '', 'authorization': '',
            'has_username': False, 'has_cookie': False, 'has_authorization': False
        }
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
                                username = decoded.split(':')[0]
                                user_info['username'] = username[:63]
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
        """Add request to user's history and display"""
        if not username: return
        try:
            user_history_map = self.bpf.get_table("user_request_history")
            username_key = user_history_map.Key(name=username.encode('utf-8')[:63])
            
            try:
                history = user_history_map[username_key]
            except KeyError:
                history = user_history_map.Leaf(
                    username=username.encode('utf-8')[:63], request_count=0
                )
            
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
        except Exception as e:
            print(f"  [⚠] Error updating user history: {e}")

    def update_resource_tracking(self, request_id, tid, first_ssl_arrival_ns=None):
        """Track resource usage for this request"""
        try:
            tid_to_req_map = self.bpf.get_table("tid_to_request_id")
            resource_map = self.bpf.get_table("request_resources")
            
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
                thread_lifetime_ns=0
            )
            
            req_key = resource_map.Key(id=request_id.encode('utf-8')[:63])
            resource_map[req_key] = usage
        except Exception as e:
            print(f"  [⚠] Error tracking resources: {e}")

    def complete_resource_tracking(self, request_id, first_ssl_arrival_ns=None):
        """Mark request as complete and calculate final metrics"""
        try:
            resource_map = self.bpf.get_table("request_resources")
            req_key = resource_map.Key(id=request_id.encode('utf-8')[:63])
            usage = resource_map[req_key]

            completion_time_ns = int(time.time_ns())
            usage.end_time_ns = completion_time_ns
            usage.duration_ns = usage.end_time_ns - usage.start_time_ns
            usage.cpu_cycles_end = usage.end_time_ns
            usage.cpu_cycles_used = usage.cpu_cycles_end - usage.cpu_cycles_start

            # =========================================================================
            # MODIFIED: Fetch actual probe overhead from BPF map. This is the core fix.
            # =========================================================================
            try:
                overhead_map = self.bpf.get_table("tid_to_overhead_ns")
                usage.system_overhead_ns = overhead_map[ctypes.c_uint(usage.tid)].value
            except KeyError:
                usage.system_overhead_ns = 0

            # Calculate total thread time (main thread + children)
            # usage.thread_lifetime_ns currently holds sum of exited threads (children + potentially main)
            try:
                thread_start_map = self.bpf.get_table("tid_to_thread_start")
                tid_key = thread_start_map.Key(usage.tid)
                thread_start_ns = thread_start_map[tid_key]
                
                # Main thread is still running (entry exists in map)
                # usage.thread_lifetime_ns currently holds exited children time
                # We add the partial lifetime of the main thread
                # Handle potentially ctypes object
                start_val = thread_start_ns.value if hasattr(thread_start_ns, 'value') else thread_start_ns
                # Get current monotonic time for duration calculation
                current_time_ns = time.monotonic_ns() 
                current_main_lifetime = current_time_ns - start_val
                usage.thread_lifetime_ns += current_main_lifetime
                
            except KeyError:
                # Main thread exited. usage.thread_lifetime_ns includes main thread's lifetime.
                if usage.thread_lifetime_ns == 0:
                    usage.thread_lifetime_ns = usage.duration_ns
            
            usage.memory_kb = max(usage.memory_kb, self._get_tid_memory_kb(usage.tid))
            usage.is_complete = 1
            resource_map[req_key] = usage

            # Display updated resource usage
            duration_ms = usage.duration_ns / 1_000_000.0
            lifetime_ms = usage.thread_lifetime_ns / 1_000_000.0
            print(f"  [⏱] Resource Usage for {request_id}:")
            print(f"      Userspace Duration: {duration_ms:.2f} ms")
            if usage.memory_kb:
                print(f"      Memory Usage: {usage.memory_kb} KB")
            print(f"      Total Thread Time: {lifetime_ms:.2f} ms")
            print(f"      Total eBPF Probe Overhead: {usage.system_overhead_ns:,} ns")

        except KeyError:
            pass # Request might not be tracked if it started before the sniffer
        except Exception as e:
            print(f"  [⚠] Error completing resource tracking: {e}")


    def _get_tid_memory_kb(self, tid):
        """Return VmRSS (kB) for a given thread id by reading /proc."""
        try:
            with open(f"/proc/{os.getpid()}/task/{tid}/status", 'r') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        return int(line.split()[1])
        except Exception:
            return 0
        return 0

    def display_user_history(self, username, history):
        """Display complete request history for a user in a formatted table."""
        print(f"\n--- User History for: {username} ---")
        
        header = f"| {'#':<3} | {'Request ID':<20} | {'Time':<8} | {'Thread':<7} | {'Source IP:Port':<21} | {'Overhead (ns)':>15} | {'Thread Time (ms)':>18} |"
        separator = '+' + '-' * 5 + '+' + '-' * 22 + '+' + '-' * 10 + '+' + '-' * 9 + '+' + '-' * 23 + '+' + '-' * 17 + '+' + '-' * 20 + '+'
        
        print(separator)
        print(header)
        print(separator)
        
        if history.request_count == 0:
            print(f"| {'No requests yet.':<122} |")
        else:
            resource_map = self.bpf.get_table("request_resources")
            for i in range(history.request_count):
                req_entry = history.requests[i]
                req_id = req_entry.request_id.decode('utf-8', 'ignore').rstrip('\x00')
                if not req_id: continue
                
                time_str = time.strftime('%H:%M:%S', time.localtime(req_entry.timestamp_ns / 1e9))
                src_ip_str = self.ip_to_str(req_entry.src_ip)
                source_str = f"{src_ip_str}:{req_entry.src_port}"

                overhead_ns = 0
                lifetime_ms = 0.0
                try:
                    req_key = resource_map.Key(id=req_id.encode('utf-8')[:63])
                    usage = resource_map[req_key]
                    overhead_ns = usage.system_overhead_ns
                    lifetime_ms = usage.thread_lifetime_ns / 1_000_000.0
                except KeyError:
                    pass
                
                print(f"| {i+1:<3} | {req_id:<20} | {time_str:<8} | {req_entry.tid:<7} | {source_str:<21} | {overhead_ns:>15,d} | {lifetime_ms:>18.2f} |")

        print(separator)
        print()

    def handle_ssl_event(self, cpu, data, size):
        """Process SSL events"""
        event = self.bpf["ssl_events"].event(data)
        tid = event.tid
        
        if tid not in self.request_buffers:
            self.request_buffers[tid] = {
                'data': b'', 'pid': event.pid, 'tid': tid,
                'comm': event.comm.decode('utf-8', 'ignore'),
                'has_conn_info': event.has_conn_info, 'src_ip': event.src_ip,
                'dst_ip': event.dst_ip, 'src_port': event.src_port, 'dst_port': event.dst_port,
                'timestamp': time.time(), 'start_time': time.time()
            }
        
        self.request_buffers[tid]['data'] += bytes(event.data[:event.data_len])
        
        if event.has_conn_info:
            self.request_buffers[tid].update({
                'has_conn_info': True, 'src_ip': event.src_ip, 'dst_ip': event.dst_ip,
                'src_port': event.src_port, 'dst_port': event.dst_port
            })
        
        full_data = self.request_buffers[tid]['data']
        if b'\r\n\r\n' in full_data or b'\n\n' in full_data:
            if full_data.startswith((b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH')):
                self.display_complete_request(tid)
            del self.request_buffers[tid]
        
        now = time.time()
        if now - self.last_cleanup > 5:
            self.last_cleanup = now
            for t in [t for t, req in self.request_buffers.items() if now - req['timestamp'] > 5]:
                del self.request_buffers[t]

    def display_complete_request(self, tid):
        """Display complete request with all tracking info"""
        req = self.request_buffers[tid]
        
        print("\n" + "="*80)
        print("HTTPS REQUEST INTERCEPTED".center(80))
        print("="*80)
        print(f"  {'Process:':<12} {req['comm']} (PID: {req['pid']}, TID: {req['tid']})")
        
        if req['has_conn_info']:
            src = f"{self.ip_to_str(req['src_ip'])}:{req['src_port']}"
            dst = f"{self.ip_to_str(req['dst_ip'])}:{req['dst_port']}"
            print(f"  {'Connection:':<12} {src} -> {dst}")
        
        headers = self.parse_http_headers(req['data'])
        request_id = self.extract_request_id(headers)
        user_info = self.extract_user_info(headers)

        print(f"  {'Request ID:':<12} {request_id}")
        if user_info['has_username']:
            print(f"  {'User:':<12} {user_info['username']}")
        
        print("-" * 80)
        print(headers.strip())
        print("-" * 80)
        
        if user_info['has_username'] and req['has_conn_info']:
            self.update_user_history(
                user_info['username'], request_id, tid, req['src_ip'], req['src_port']
            )
        
        self.update_resource_tracking(request_id, tid)
        self.complete_resource_tracking(request_id)
        print()

    def display_all_summaries(self):
        """Display all tracking summaries on exit"""
        self.display_resource_summary()
        self.display_user_histories(summary_mode=True)

    def display_resource_summary(self):
        """Display resource usage summary in a formatted table."""
        print("\n" + "="*80)
        print("📊 RESOURCE USAGE SUMMARY".center(80))
        print("="*80)
        
        try:
            resource_map = self.bpf.get_table("request_resources")
            if not resource_map:
                print("No resource data tracked.")
                return

            header = f"| {'Request ID':<20} | {'Duration (ms)':>15} | {'Overhead (ns)':>15} | {'Thread Time (ms)':>18} | {'Memory (KB)':>12} | {'Status':<10} |"
            separator = '+' + '-'*22 + '+' + '-'*17 + '+' + '-'*17 + '+' + '-'*20 + '+' + '-'*14 + '+' + '-'*12 + '+'
            
            print(separator)
            print(header)
            print(separator)
            
            for req_id_key, usage in sorted(resource_map.items(), key=lambda item: item[1].start_time_ns):
                req_id = req_id_key.id.decode('utf-8', 'ignore').rstrip('\x00')
                if not req_id: continue
                
                duration_ms = usage.duration_ns / 1e6
                overhead_ns = usage.system_overhead_ns
                lifetime_ms = usage.thread_lifetime_ns / 1e6
                status = "Complete" if usage.is_complete else "In-Flight"
                mem_kb = usage.memory_kb if usage.memory_kb else 0

                print(f"| {req_id:<20} | {duration_ms:>15.2f} | {overhead_ns:>15,d} | {lifetime_ms:>15.2f} | {mem_kb:>12,d} | {status:<10} |")

            print(separator)
        except Exception as e:
            print(f"  Error displaying resource summary: {e}")

    def display_user_histories(self, summary_mode=False):
        """Display all user request histories."""
        if not summary_mode: return # This is now handled live
        
        print("\n" + "="*80)
        print("👥 ALL USER HISTORIES".center(80))
        print("="*80)
        
        try:
            user_history_map = self.bpf.get_table("user_request_history")
            if not user_history_map:
                print("No user histories tracked.")
            else:
                for username_key, history in user_history_map.items():
                    username = username_key.name.decode('utf-8', 'ignore').rstrip('\x00')
                    if username:
                        self.display_user_history(username, history)
        except Exception as e:
            print(f"  Error displaying user histories: {e}")

    def run(self):
        """Main execution"""
        print("="*80)
        print("🔍 Integrated HTTPS Server Sniffer".center(80))
        print("="*80)
        print("Initializing eBPF probes... (This may take a moment)")
        
        try:
            self.bpf = BPF(text=BPF_PROGRAM)
            ssl_lib_path = BPF.find_library("ssl") or "/usr/lib/libssl.so.3"
            print(f"Found SSL library at: {ssl_lib_path}")

            self.bpf.attach_uprobe(name=ssl_lib_path, sym="SSL_read", fn_name="probe_ssl_read_enter")
            self.bpf.attach_uretprobe(name=ssl_lib_path, sym="SSL_read", fn_name="probe_ssl_read_exit")
            print("✓ Attached to SSL_read")
            
            try:
                self.bpf.attach_uprobe(name=ssl_lib_path, sym="SSL_read_ex", fn_name="probe_ssl_read_ex_enter")
                self.bpf.attach_uretprobe(name=ssl_lib_path, sym="SSL_read_ex", fn_name="probe_ssl_read_ex_exit")
                print("✓ Attached to SSL_read_ex")
            except Exception:
                print("ℹ SSL_read_ex not found, skipping.")
            
            print("\n" + "="*80)
            print("🎯 Monitoring HTTPS traffic... Press Ctrl+C to stop.".center(80))
            print("="*80)
            
            self.bpf["ssl_events"].open_perf_buffer(self.handle_ssl_event)
            while True:
                try:
                    self.bpf.perf_buffer_poll(timeout=100)
                except KeyboardInterrupt:
                    print("\n\n🛑 Stopping sniffer...")
                    self.display_all_summaries()
                    break
        except Exception as e:
            print(f"\n[ERROR] Failed to initialize eBPF program: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root!")
        exit(1)
    sniffer = IntegratedSniffer()
    sniffer.run()