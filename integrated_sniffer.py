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

# Combined eBPF Program
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
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;
    
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
            # Many kernels deliver sk addresses read into u32 that appear in host
            # order on little-endian machines. Use little-endian packing which
            # renders 127.0.0.1 correctly when the raw value is 0x0100007f.
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
        # Try to find X-Request-ID header
        for line in headers_text.split('\n'):
            line = line.strip()
            if line.lower().startswith('x-request-id:'):
                return line[13:].strip()[:63]
        
        # Try to extract from query params (e.g., ?id=REQ001)
        first_line = headers_text.split('\n')[0] if headers_text else ""
        match = re.search(r'[?&]id=([^&\s]+)', first_line)
        if match:
            return match.group(1)[:63]
        
        # Generate unique ID
        self.request_counter += 1
        return f"AUTO_{self.request_counter:06d}"
    
    def extract_user_info(self, headers_text):
        """Extract username, cookie, and authorization from headers"""
        user_info = {
            'username': '',
            'cookie': '',
            'authorization': '',
            'has_username': False,
            'has_cookie': False,
            'has_authorization': False
        }
        
        try:
            for line in headers_text.split('\n'):
                line = line.strip()
                
                if line.lower().startswith('cookie:'):
                    cookie_value = line[7:].strip()
                    user_info['cookie'] = cookie_value[:255]
                    user_info['has_cookie'] = True
                    
                    # Extract username from cookie
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
                            encoded = auth_value[6:]
                            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                            if ':' in decoded:
                                username = decoded.split(':')[0]
                                user_info['username'] = username[:63]
                                user_info['has_username'] = True
                        except:
                            pass
                
                elif not user_info['has_username']:
                    if line.lower().startswith('x-user:') or line.lower().startswith('x-username:'):
                        colon_pos = line.find(':')
                        if colon_pos > 0:
                            username = line[colon_pos+1:].strip()
                            user_info['username'] = username[:63]
                            user_info['has_username'] = True
        except:
            pass
        
        return user_info
    
    def update_user_history(self, username, request_id, tid, src_ip, src_port):
        """Add request to user's history and display"""
        if not username:
            return
        
        try:
            user_history_map = self.bpf.get_table("user_request_history")
            
            # Create username key struct
            username_key = user_history_map.Key()
            username_key.name = username.encode('utf-8')[:63] + b'\x00'
            
            try:
                history = user_history_map[username_key]
                request_count = history.request_count
            except KeyError:
                history = user_history_map.Leaf()
                history.username = username.encode('utf-8')[:63] + b'\x00'
                history.request_count = 0
                request_count = 0
            
            idx = request_count
            if idx >= 100:
                # Shift array
                for i in range(99):
                    history.requests[i] = history.requests[i + 1]
                idx = 99
            else:
                history.request_count += 1
            
            # Add new request
            history.requests[idx].request_id = request_id.encode('utf-8')[:63] + b'\x00'
            history.requests[idx].timestamp_ns = int(time.time() * 1_000_000_000)
            history.requests[idx].tid = tid
            history.requests[idx].src_ip = src_ip
            history.requests[idx].src_port = src_port
            history.last_updated_ns = int(time.time() * 1_000_000_000)
            
            user_history_map[username_key] = history
            
            # Display updated history
            self.display_user_history(username, history)
            
        except Exception as e:
            print(f"  [⚠] Error updating user history: {e}")
    
    def update_resource_tracking(self, request_id, tid):
        """Track resource usage for this request"""
        try:
            tid_to_req_map = self.bpf.get_table("tid_to_request_id")
            resource_map = self.bpf.get_table("request_resources")
            
            # Create request ID key struct
            req_id_key = tid_to_req_map.Leaf()
            req_id_key.id = request_id.encode('utf-8')[:63] + b'\x00'
            
            # Store TID → Request ID
            tid_key = tid_to_req_map.Key(tid)
            tid_to_req_map[tid_key] = req_id_key
            
            # Initialize resource tracking
            usage = resource_map.Leaf()
            usage.request_id = request_id.encode('utf-8')[:63] + b'\x00'
            usage.tid = tid
            usage.start_time_ns = int(time.time() * 1_000_000_000)
            usage.cpu_cycles_start = usage.start_time_ns  # Approximation
            usage.memory_kb = self._get_tid_memory_kb(tid)
            usage.is_complete = 0
            
            # Use struct key for resource map
            req_key = resource_map.Key()
            req_key.id = request_id.encode('utf-8')[:63] + b'\x00'
            resource_map[req_key] = usage
            
        except Exception as e:
            print(f"  [⚠] Error tracking resources: {e}")
    
    def complete_resource_tracking(self, request_id):
        """Mark request as complete and calculate final metrics"""
        try:
            resource_map = self.bpf.get_table("request_resources")
            
            # Create request ID key struct
            req_key = resource_map.Key()
            req_key.id = request_id.encode('utf-8')[:63] + b'\x00'
            
            usage = resource_map[req_key]
            usage.end_time_ns = int(time.time() * 1_000_000_000)
            usage.cpu_cycles_end = usage.end_time_ns
            usage.duration_ns = usage.end_time_ns - usage.start_time_ns
            usage.cpu_cycles_used = usage.cpu_cycles_end - usage.cpu_cycles_start
            # Refresh memory usage at completion
            usage.memory_kb = max(usage.memory_kb, self._get_tid_memory_kb(usage.tid))
            usage.is_complete = 1
            
            resource_map[req_key] = usage
            
            # Display resource usage
            duration_ms = usage.duration_ns / 1_000_000.0
            print(f"  [⏱] Resource Usage for {request_id}:")
            print(f"      Duration: {duration_ms:.2f} ms")
            print(f"      CPU Cycles: {usage.cpu_cycles_used:,}")
            if usage.memory_kb:
                print(f"      Memory: {usage.memory_kb} KB")
            
        except Exception as e:
            pass  # Request might not be tracked

    def _get_tid_memory_kb(self, tid):
        """Return VmRSS (kB) for a given thread id by reading /proc."""
        try:
            pid = os.getpid()
            status_path = f"/proc/{pid}/task/{tid}/status"
            with open(status_path, 'r') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1])  # already in kB
        except Exception:
            return 0
        return 0
    
    def display_user_history(self, username, history):
        """Display complete request history for a user"""
        print("\n" + "╔" + "═" * 78 + "╗")
        print(f"║ 👤 USER: {username:67} ║")
        print("╠" + "═" * 78 + "╣")
        
        count = history.request_count
        print(f"║ Total Requests: {count:63} ║")
        print("╠" + "═" * 78 + "╣")
        
        if count == 0:
            print("║ No requests yet" + " " * 62 + "║")
        else:
            print("║ #  │ Request ID          │ Time     │ Thread  │ Source IP:Port      ║")
            print("╠" + "═" * 78 + "╣")
            
            for i in range(min(count, 100)):
                req_entry = history.requests[i]
                req_id = req_entry.request_id.decode('utf-8', errors='ignore').rstrip('\x00')
                
                if not req_id:
                    continue
                
                ts_sec = req_entry.timestamp_ns / 1_000_000_000
                time_str = time.strftime('%H:%M:%S', time.localtime(ts_sec))
                src_ip_str = self.ip_to_str(req_entry.src_ip)
                
                print(f"║ {i+1:2} │ {req_id:19} │ {time_str} │ {req_entry.tid:7} │ {src_ip_str:15}:{req_entry.src_port:5} ║")
        
        print("╚" + "═" * 78 + "╝\n")
    
    def handle_ssl_event(self, cpu, data, size):
        """Process SSL events"""
        event = self.bpf["ssl_events"].event(data)
        tid = event.tid
        data_bytes = bytes(event.data[:event.data_len])
        
        if tid not in self.request_buffers:
            self.request_buffers[tid] = {
                'data': b'',
                'pid': event.pid,
                'tid': tid,
                'comm': event.comm.decode('utf-8', 'ignore'),
                'has_conn_info': event.has_conn_info,
                'src_ip': event.src_ip,
                'dst_ip': event.dst_ip,
                'src_port': event.src_port,
                'dst_port': event.dst_port,
                'timestamp': time.time(),
                'start_time': time.time()
            }
        
        self.request_buffers[tid]['data'] += data_bytes
        
        if event.has_conn_info:
            self.request_buffers[tid]['has_conn_info'] = True
            self.request_buffers[tid]['src_ip'] = event.src_ip
            self.request_buffers[tid]['dst_ip'] = event.dst_ip
            self.request_buffers[tid]['src_port'] = event.src_port
            self.request_buffers[tid]['dst_port'] = event.dst_port
        
        full_data = self.request_buffers[tid]['data']
        if b'\r\n\r\n' in full_data or b'\n\n' in full_data:
            if (full_data.startswith(b'GET') or full_data.startswith(b'POST') or
                full_data.startswith(b'PUT') or full_data.startswith(b'DELETE') or
                full_data.startswith(b'HEAD') or full_data.startswith(b'OPTIONS') or
                full_data.startswith(b'PATCH')):
                
                self.display_complete_request(tid)
            
            del self.request_buffers[tid]
        
        # Cleanup
        now = time.time()
        if now - self.last_cleanup > 5:
            self.last_cleanup = now
            expired = [t for t, req in self.request_buffers.items()
                      if now - req['timestamp'] > 5]
            for t in expired:
                del self.request_buffers[t]
    
    def display_complete_request(self, tid):
        """Display complete request with all tracking info"""
        req = self.request_buffers[tid]
        
        print("\n" + "=" * 80)
        print("[HTTPS REQUEST INTERCEPTED]")
        print("=" * 80)
        print(f"Process ID (PID):        {req['pid']}")
        print(f"Thread ID (TID):         {req['tid']}")
        print(f"Process Name:            {req['comm']}")
        
        # Connection info
        if req['has_conn_info']:
            src_ip = self.ip_to_str(req['src_ip'])
            dst_ip = self.ip_to_str(req['dst_ip'])
            print(f"\nConnection 4-tuple:")
            print(f"  Source:      {src_ip}:{req['src_port']} (client)")
            print(f"  Destination: {dst_ip}:{req['dst_port']} (server)")
        else:
            print(f"\nConnection Info: [Not available]")
        
        # HTTP headers
        headers = self.parse_http_headers(req['data'])
        print(f"\nHTTP Request Headers:")
        print("-" * 80)
        print(headers)
        print("-" * 80)
        
        # Extract request ID
        request_id = self.extract_request_id(headers)
        print(f"\n📝 Request ID: {request_id}")
        
        # Extract user info
        user_info = self.extract_user_info(headers)
        
        if user_info['has_username'] or user_info['has_cookie'] or user_info['has_authorization']:
            print(f"\n👤 User Information:")
            print("-" * 80)
            if user_info['has_username']:
                print(f"  Username:      {user_info['username']}")
            if user_info['has_cookie']:
                print(f"  Cookie:        {user_info['cookie']}")
            if user_info['has_authorization']:
                print(f"  Authorization: {user_info['authorization']}")
            print("-" * 80)
            
            # Update tid_to_user_info map
            self.update_user_info_map(tid, user_info)
            
            # Update user request history
            if user_info['has_username'] and req['has_conn_info']:
                self.update_user_history(
                    user_info['username'],
                    request_id,
                    tid,
                    req['src_ip'],
                    req['src_port']
                )
        
        # Resource tracking
        self.update_resource_tracking(request_id, tid)
        
        # Mark as complete
        duration = time.time() - req['start_time']
        print(f"\n⏱ Processing Time: {duration*1000:.2f} ms")
        
        self.complete_resource_tracking(request_id)
        
        print()
    
    def update_user_info_map(self, tid, user_info):
        """Update tid_to_user_info BPF map"""
        try:
            user_info_map = self.bpf.get_table("tid_to_user_info")
            info_struct = user_info_map.Leaf()
            
            if user_info['has_username']:
                info_struct.username = user_info['username'].encode('utf-8')[:63] + b'\x00'
                info_struct.has_username = 1
            
            if user_info['has_cookie']:
                info_struct.cookie = user_info['cookie'].encode('utf-8')[:255] + b'\x00'
                info_struct.has_cookie = 1
            
            if user_info['has_authorization']:
                info_struct.authorization = user_info['authorization'].encode('utf-8')[:127] + b'\x00'
                info_struct.has_authorization = 1
            
            tid_key = user_info_map.Key(tid)
            user_info_map[tid_key] = info_struct
            
        except Exception as e:
            print(f"  [⚠] Could not update user info map: {e}")
    
    def display_all_summaries(self):
        """Display all tracking summaries on exit"""
        self.display_resource_summary()
        self.display_user_histories()
    
    def display_resource_summary(self):
        """Display resource usage summary"""
        print("\n" + "=" * 80)
        print("📊 RESOURCE USAGE SUMMARY")
        print("=" * 80)
        
        try:
            resource_map = self.bpf.get_table("request_resources")
            
            if len(resource_map) == 0:
                print("  No resource data tracked.")
            else:
                print(f"  Total requests tracked: {len(resource_map)}\n")
                print(f"  {'Request ID':<20} │ {'Duration':<12} │ {'CPU Cycles':<15} │ {'Memory':<10} │ {'Status':<10}")
                print("  " + "-" * 90)
                
                for req_id_key, usage in resource_map.items():
                    request_id = req_id_key.id.decode('utf-8', errors='ignore').rstrip('\x00')
                    if not request_id:
                        continue
                    
                    duration_ms = usage.duration_ns / 1_000_000.0 if usage.duration_ns > 0 else 0
                    status = "Complete" if usage.is_complete else "In Progress"
                    mem_str = f"{usage.memory_kb} KB" if usage.memory_kb else "-"
                    
                    print(f"  {request_id:<20} │ {duration_ms:>10.2f} ms │ {usage.cpu_cycles_used:>13,} │ {mem_str:>10} │ {status:<10}")
        except Exception as e:
            print(f"  Error: {e}")
        
        print("=" * 80)
    
    def display_user_histories(self):
        """Display all user request histories"""
        print("\n" + "=" * 80)
        print("👥 USER REQUEST HISTORIES")
        print("=" * 80)
        
        try:
            user_history_map = self.bpf.get_table("user_request_history")
            
            if len(user_history_map) == 0:
                print("  No user histories tracked.")
            else:
                print(f"  Total users tracked: {len(user_history_map)}\n")
                
                for username_key, history in user_history_map.items():
                    username = username_key.name.decode('utf-8', errors='ignore').rstrip('\x00')
                    if username:
                        self.display_user_history(username, history)
        except Exception as e:
            print(f"  Error: {e}")
        
        print("=" * 80)
    
    def run(self):
        """Main execution"""
        print("=" * 80)
        print("🔍 Integrated HTTPS Server Sniffer")
        print("=" * 80)
        print("Features:")
        print("  ✓ Connection attribution (TID → FD → Connection)")
        print("  ✓ User information extraction")
        print("  ✓ Resource usage tracking per request")
        print("  ✓ User request history tracking")
        print("=" * 80)
        print("\nInitializing eBPF probes...\n")
        
        try:
            self.bpf = BPF(text=BPF_PROGRAM)
            
            ssl_lib = "/usr/lib/libssl.so.3"
            
            try:
                self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read",
                                      fn_name="probe_ssl_read_enter")
                self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read",
                                         fn_name="probe_ssl_read_exit")
                print(f"✓ Attached to SSL_read")
            except Exception as e:
                print(f"⚠ Could not attach to SSL_read: {e}")
            
            try:
                self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read_ex",
                                      fn_name="probe_ssl_read_ex_enter")
                self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read_ex",
                                         fn_name="probe_ssl_read_ex_exit")
                print(f"✓ Attached to SSL_read_ex")
            except Exception as e:
                print(f"⚠ Could not attach to SSL_read_ex: {e}")
            
            print("\n" + "=" * 80)
            print("🎯 Monitoring HTTPS traffic...")
            print("   All features active: connection, user info, resources, history")
            print("=" * 80)
            print()
            
            self.bpf["ssl_events"].open_perf_buffer(self.handle_ssl_event)
            
            while True:
                try:
                    self.bpf.perf_buffer_poll(timeout=100)
                except KeyboardInterrupt:
                    print("\n\n🛑 Stopping sniffer...")
                    self.display_all_summaries()
                    break
                    
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    import os
    
    if os.geteuid() != 0:
        print("This program must be run as root!")
        print("Usage: sudo python3 integrated_sniffer.py")
        exit(1)
    
    sniffer = IntegratedSniffer()
    sniffer.run()

