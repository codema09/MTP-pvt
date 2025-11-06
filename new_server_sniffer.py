#!/usr/bin/env python3
"""
HTTPS Server Sniffer - Clean Architecture
==========================================
This program captures HTTPS request headers with proper connection attribution.

Design Philosophy:
1. Don't track at accept() time - let kernel handle FD allocation
2. On first recv() on an FD: Walk kernel structures to get socket → connection
3. Cache FD→Connection and TID→FD mappings
4. On SSL_read: Simple lookup chain TID → FD → Connection

This eliminates all race conditions from accept correlation.

Usage: sudo python3 new_server_sniffer.py
"""

from bcc import BPF
import socket
import struct

# eBPF Program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/net.h>

#define MAX_HEADER_SIZE 1024

// Connection 4-tuple structure
struct conn_tuple_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

// User information extracted from HTTP headers
#define MAX_USERNAME_LEN 64
#define MAX_COOKIE_LEN 256
#define MAX_AUTH_LEN 128

struct user_info_t {
    char username[MAX_USERNAME_LEN];
    char cookie[MAX_COOKIE_LEN];
    char authorization[MAX_AUTH_LEN];
    u8 has_username;
    u8 has_cookie;
    u8 has_authorization;
};

// Event structure sent to userspace
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
// STORAGE MAPS
// ═══════════════════════════════════════════════════════════════

// Output channel (must be declared before use!)
BPF_PERF_OUTPUT(ssl_events);

// Primary mappings (persistent)
BPF_HASH(fd_to_conn, u32, struct conn_tuple_t);  // FD → Connection
BPF_HASH(tid_to_fd, u64, u32);                    // Thread → FD

// NEW: User information mapping (TID → User Info from headers)
BPF_HASH(tid_to_user_info, u32, struct user_info_t);

// Temporary storage for function arguments
BPF_HASH(ssl_read_args, u64, void *);            // TID → buffer pointer

// Per-CPU scratch space (avoids memset issues)
BPF_PERCPU_ARRAY(event_scratch, struct ssl_data_event_t, 1);

// ═══════════════════════════════════════════════════════════════
// HELPER: Get socket from FD (walks kernel structures)
// ═══════════════════════════════════════════════════════════════

static struct sock* get_sock_from_fd(u32 fd) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Get files structure
    struct files_struct *files = task->files;
    if (files == NULL) {
        return NULL;
    }
    
    // Get fd table
    struct fdtable *fdt = files->fdt;
    if (fdt == NULL) {
        return NULL;
    }
    
    // Bounds check
    if (fd >= fdt->max_fds) {
        return NULL;
    }
    
    // Get file structure for this FD
    struct file **fd_array;
    bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    
    struct file *file;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    
    if (file == NULL) {
        return NULL;
    }
    
    // Get socket from file
    struct socket *sock_obj;
    bpf_probe_read_kernel(&sock_obj, sizeof(sock_obj), &file->private_data);
    
    if (sock_obj == NULL) {
        return NULL;
    }
    
    // Get sock structure
    struct sock *sk;
    bpf_probe_read_kernel(&sk, sizeof(sk), &sock_obj->sk);
    
    return sk;
}

// ═══════════════════════════════════════════════════════════════
// STEP 1: First recv() on an FD - Establish FD→Connection mapping
// ═══════════════════════════════════════════════════════════════

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 fd = (u32)args->fd;
    
    // Check if we've already mapped this FD
    struct conn_tuple_t *existing = fd_to_conn.lookup(&fd);
    if (existing != NULL) {
        // Already mapped, just update TID→FD
        tid_to_fd.update(&pid_tgid, &fd);
        return 0;
    }
    
    // First time seeing this FD - extract connection from kernel
    struct sock *sk = get_sock_from_fd(fd);
    if (sk == NULL) {
        // Not a socket FD, ignore
        return 0;
    }
    
    // Check if it's IPv4
    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) {
        return 0;  // IPv6 or other, skip for now
    }
    
    // Extract connection 4-tuple from socket structure
    struct conn_tuple_t conn;
    bpf_probe_read_kernel(&conn.src_ip, sizeof(u32), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&conn.dst_ip, sizeof(u32), &sk->__sk_common.skc_rcv_saddr);
    
    u16 src_port_be, dst_port_host;
    bpf_probe_read_kernel(&src_port_be, sizeof(u16), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&dst_port_host, sizeof(u16), &sk->__sk_common.skc_num);
    
    conn.src_port = bpf_ntohs(src_port_be);
    conn.dst_port = dst_port_host;
    
    // CRITICAL MAPPINGS (established atomically on first recv):
    // a) FD → Connection
    fd_to_conn.update(&fd, &conn);
    
    // b) TID → FD
    tid_to_fd.update(&pid_tgid, &fd);
    
    return 0;
}

// Also handle regular read() syscall
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;
    
    // Check if already mapped
    struct conn_tuple_t *existing = fd_to_conn.lookup(&fd);
    if (existing != NULL) {
        tid_to_fd.update(&pid_tgid, &fd);
        return 0;
    }
    
    // First time - extract from kernel
    struct sock *sk = get_sock_from_fd(fd);
    if (sk == NULL) {
        return 0;
    }
    
    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET) {
        return 0;
    }
    
    // Extract connection 4-tuple
    struct conn_tuple_t conn;
    bpf_probe_read_kernel(&conn.src_ip, sizeof(u32), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&conn.dst_ip, sizeof(u32), &sk->__sk_common.skc_rcv_saddr);
    
    u16 src_port_be, dst_port_host;
    bpf_probe_read_kernel(&src_port_be, sizeof(u16), &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&dst_port_host, sizeof(u16), &sk->__sk_common.skc_num);
    
    conn.src_port = bpf_ntohs(src_port_be);
    conn.dst_port = dst_port_host;
    
    // Establish mappings
    fd_to_conn.update(&fd, &conn);
    tid_to_fd.update(&pid_tgid, &fd);
    
    return 0;
}

// ═══════════════════════════════════════════════════════════════
// STEP 2: SSL_read - Capture decrypted data and attribute
// ═══════════════════════════════════════════════════════════════

// For SSL_read: int SSL_read(SSL *ssl, void *buf, int num)
int probe_ssl_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ssl_read_args.update(&pid_tgid, &buf);
    return 0;
}

int probe_ssl_read_exit(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;  // No data read
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // Get buffer pointer
    void **buf_ptr = ssl_read_args.lookup(&pid_tgid);
    if (buf_ptr == NULL) {
        return 0;
    }
    void *buf = *buf_ptr;
    ssl_read_args.delete(&pid_tgid);
    
    // Get scratch space
    u32 zero = 0;
    struct ssl_data_event_t *evt = event_scratch.lookup(&zero);
    if (evt == NULL) {
        return 0;
    }
    
    // Initialize event
    evt->pid = pid;
    evt->tid = tid;
    evt->has_conn_info = 0;
    evt->src_ip = 0;
    evt->dst_ip = 0;
    evt->src_port = 0;
    evt->dst_port = 0;
    
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Copy decrypted data
    u32 copy_len = (u32)ret;
    if (copy_len > MAX_HEADER_SIZE) {
        copy_len = MAX_HEADER_SIZE;
    }
    bpf_probe_read_user(&evt->data, copy_len, buf);
    evt->data_len = copy_len;
    
    // ATTRIBUTION: TID → FD → Connection
    u32 *fd_ptr = tid_to_fd.lookup(&pid_tgid);
    if (fd_ptr != NULL) {
        u32 fd = *fd_ptr;
        struct conn_tuple_t *conn = fd_to_conn.lookup(&fd);
        if (conn != NULL) {
            evt->src_ip = conn->src_ip;
            evt->dst_ip = conn->dst_ip;
            evt->src_port = conn->src_port;
            evt->dst_port = conn->dst_port;
            evt->has_conn_info = 1;
        }
    }
    
    // Send to userspace
    ssl_events.perf_submit(ctx, evt, sizeof(*evt));
    
    return 0;
}

// For SSL_read_ex: int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
struct ssl_read_ex_args_t {
    void *buf;
    void *readbytes_ptr;
};

BPF_HASH(ssl_read_ex_args, u64, struct ssl_read_ex_args_t);

int probe_ssl_read_ex_enter(struct pt_regs *ctx, void *ssl, void *buf, 
                             unsigned long num, void *readbytes) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct ssl_read_ex_args_t args = {
        .buf = buf,
        .readbytes_ptr = readbytes,
    };
    ssl_read_ex_args.update(&pid_tgid, &args);
    return 0;
}

int probe_ssl_read_ex_exit(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret != 1) {  // SSL_read_ex returns 1 on success
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // Get saved arguments
    struct ssl_read_ex_args_t *args = ssl_read_ex_args.lookup(&pid_tgid);
    if (args == NULL) {
        return 0;
    }
    
    // Read actual bytes read
    unsigned long bytes_read = 0;
    bpf_probe_read_user(&bytes_read, sizeof(bytes_read), args->readbytes_ptr);
    
    if (bytes_read <= 0) {
        ssl_read_ex_args.delete(&pid_tgid);
        return 0;
    }
    
    void *buf = args->buf;
    ssl_read_ex_args.delete(&pid_tgid);
    
    // Get scratch space
    u32 zero = 0;
    struct ssl_data_event_t *evt = event_scratch.lookup(&zero);
    if (evt == NULL) {
        return 0;
    }
    
    // Initialize event
    evt->pid = pid;
    evt->tid = tid;
    evt->has_conn_info = 0;
    evt->src_ip = 0;
    evt->dst_ip = 0;
    evt->src_port = 0;
    evt->dst_port = 0;
    
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Copy decrypted data
    u32 copy_len = (u32)bytes_read;
    if (copy_len > MAX_HEADER_SIZE) {
        copy_len = MAX_HEADER_SIZE;
    }
    bpf_probe_read_user(&evt->data, copy_len, buf);
    evt->data_len = copy_len;
    
    // ATTRIBUTION: TID → FD → Connection
    u32 *fd_ptr = tid_to_fd.lookup(&pid_tgid);
    if (fd_ptr != NULL) {
        u32 fd = *fd_ptr;
        struct conn_tuple_t *conn = fd_to_conn.lookup(&fd);
        if (conn != NULL) {
            evt->src_ip = conn->src_ip;
            evt->dst_ip = conn->dst_ip;
            evt->src_port = conn->src_port;
            evt->dst_port = conn->dst_port;
            evt->has_conn_info = 1;
        }
    }
    
    // Send to userspace
    ssl_events.perf_submit(ctx, evt, sizeof(*evt));
    
    return 0;
}
"""

# ═══════════════════════════════════════════════════════════════
# PYTHON USERSPACE PROGRAM
# ═══════════════════════════════════════════════════════════════

class HTTPSServerSniffer:
    def __init__(self):
        self.bpf = None
        self.request_buffers = {}  # tid → accumulated data
        self.last_cleanup = 0
        
    def ip_to_str(self, ip):
        """Convert IP from network byte order to string"""
        return socket.inet_ntoa(struct.pack("I", ip))
    
    def parse_http_headers(self, data):
        """Extract HTTP headers from raw data"""
        try:
            text = data.decode('utf-8', errors='ignore')
            
            # Find end of headers
            header_end = text.find('\r\n\r\n')
            if header_end == -1:
                header_end = text.find('\n\n')
                if header_end == -1:
                    header_end = len(text)
            
            return text[:header_end]
        except Exception as e:
            return f"[Parse error: {e}]"
    
    def extract_user_info(self, headers_text):
        """Extract username, cookie, and authorization from HTTP headers"""
        user_info = {
            'username': '',
            'cookie': '',
            'authorization': '',
            'has_username': 0,
            'has_cookie': 0,
            'has_authorization': 0
        }
        
        try:
            lines = headers_text.split('\n')
            for line in lines:
                line = line.strip()
                
                # Extract Cookie header
                if line.lower().startswith('cookie:'):
                    cookie_value = line[7:].strip()
                    user_info['cookie'] = cookie_value[:255]  # Limit to 255 chars
                    user_info['has_cookie'] = 1
                    
                    # Try to extract username from cookie
                    for part in cookie_value.split(';'):
                        part = part.strip()
                        if '=' in part:
                            key, val = part.split('=', 1)
                            if key.lower() in ['user', 'username', 'user_id']:
                                user_info['username'] = val[:63]
                                user_info['has_username'] = 1
                                break
                
                # Extract Authorization header
                elif line.lower().startswith('authorization:'):
                    auth_value = line[14:].strip()
                    user_info['authorization'] = auth_value[:127]  # Limit to 127 chars
                    user_info['has_authorization'] = 1
                    
                    # Try to extract username from Basic auth
                    if auth_value.lower().startswith('basic '):
                        try:
                            import base64
                            encoded = auth_value[6:]
                            decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                            if ':' in decoded:
                                username = decoded.split(':')[0]
                                user_info['username'] = username[:63]
                                user_info['has_username'] = 1
                        except:
                            pass
                
                # Look for username in other headers
                elif not user_info['has_username']:
                    if line.lower().startswith('x-user:') or line.lower().startswith('x-username:'):
                        colon_pos = line.find(':')
                        if colon_pos > 0:
                            username = line[colon_pos+1:].strip()
                            user_info['username'] = username[:63]
                            user_info['has_username'] = 1
        except Exception as e:
            pass
        
        return user_info
    
    def handle_ssl_event(self, cpu, data, size):
        """Process SSL read events from eBPF"""
        import time
        
        event = self.bpf["ssl_events"].event(data)
        tid = event.tid
        data_bytes = bytes(event.data[:event.data_len])
        
        # Initialize buffer for this TID if first chunk
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
                'timestamp': time.time()
            }
        
        # Accumulate data
        self.request_buffers[tid]['data'] += data_bytes
        
        # Update connection info if available
        if event.has_conn_info:
            self.request_buffers[tid]['has_conn_info'] = True
            self.request_buffers[tid]['src_ip'] = event.src_ip
            self.request_buffers[tid]['dst_ip'] = event.dst_ip
            self.request_buffers[tid]['src_port'] = event.src_port
            self.request_buffers[tid]['dst_port'] = event.dst_port
        
        # Check for complete HTTP request
        full_data = self.request_buffers[tid]['data']
        if b'\r\n\r\n' in full_data or b'\n\n' in full_data:
            # Verify it's an HTTP request
            if (full_data.startswith(b'GET') or full_data.startswith(b'POST') or
                full_data.startswith(b'PUT') or full_data.startswith(b'DELETE') or
                full_data.startswith(b'HEAD') or full_data.startswith(b'OPTIONS') or
                full_data.startswith(b'PATCH')):
                
                self.display_request(tid)
            
            # Clean up
            del self.request_buffers[tid]
        
        # Periodic cleanup of stale buffers
        now = time.time()
        if now - self.last_cleanup > 5:
            self.last_cleanup = now
            expired = [t for t, req in self.request_buffers.items() 
                      if now - req['timestamp'] > 5]
            for t in expired:
                del self.request_buffers[t]
    
    def display_request(self, tid):
        """Display complete HTTPS request and update user info map"""
        req = self.request_buffers[tid]
        
        print("=" * 80)
        print("[HTTPS REQUEST INTERCEPTED]")
        print("=" * 80)
        print(f"Process ID (PID):        {req['pid']}")
        print(f"Thread ID (TID):         {req['tid']}")
        print(f"Process Name:            {req['comm']}")
        
        if req['has_conn_info']:
            src_ip = self.ip_to_str(req['src_ip'])
            dst_ip = self.ip_to_str(req['dst_ip'])
            print(f"\nConnection 4-tuple:")
            print(f"  Source:      {src_ip}:{req['src_port']} (client)")
            print(f"  Destination: {dst_ip}:{req['dst_port']} (server)")
        else:
            print(f"\nConnection Info: [Not available - FD not tracked yet]")
        
        # Parse and display headers
        headers = self.parse_http_headers(req['data'])
        print(f"\nHTTP Request Headers:")
        print("-" * 80)
        print(headers)
        print("-" * 80)
        
        # Extract and display user information
        user_info = self.extract_user_info(headers)
        
        if user_info['has_username'] or user_info['has_cookie'] or user_info['has_authorization']:
            print(f"\nExtracted User Information:")
            print("-" * 80)
            if user_info['has_username']:
                print(f"  Username:      {user_info['username']}")
            if user_info['has_cookie']:
                print(f"  Cookie:        {user_info['cookie']}")
            if user_info['has_authorization']:
                print(f"  Authorization: {user_info['authorization']}")
            print("-" * 80)
            
            # Update BPF map: tid_to_user_info
            self.update_user_info_map(tid, user_info)
        
        print()
    
    def update_user_info_map(self, tid, user_info):
        """Update the BPF map with user information for this TID"""
        try:
            # Create C struct to match kernel definition
            user_info_struct = self.bpf["tid_to_user_info"].Leaf()
            
            # Populate fields (only if present)
            if user_info['has_username']:
                user_info_struct.username = user_info['username'].encode('utf-8')[:63] + b'\x00'
                user_info_struct.has_username = 1
            else:
                user_info_struct.has_username = 0
            
            if user_info['has_cookie']:
                user_info_struct.cookie = user_info['cookie'].encode('utf-8')[:255] + b'\x00'
                user_info_struct.has_cookie = 1
            else:
                user_info_struct.has_cookie = 0
            
            if user_info['has_authorization']:
                user_info_struct.authorization = user_info['authorization'].encode('utf-8')[:127] + b'\x00'
                user_info_struct.has_authorization = 1
            else:
                user_info_struct.has_authorization = 0
            
            # Update map (key is TID as u32)
            tid_key = self.bpf["tid_to_user_info"].Key(tid)
            self.bpf["tid_to_user_info"][tid_key] = user_info_struct
            
            print(f"  [✓] Updated tid_to_user_info[{tid}] in BPF map")
            
        except Exception as e:
            print(f"  [⚠] Could not update BPF map: {e}")
    
    def print_user_info_summary(self):
        """Display summary of all tracked user information"""
        print("\n" + "=" * 80)
        print("SUMMARY: User Information Tracked in BPF Map")
        print("=" * 80)
        
        tid_to_user_info = self.bpf.get_table("tid_to_user_info")
        
        if len(tid_to_user_info) == 0:
            print("  No user information tracked.")
        else:
            print(f"  Total threads tracked: {len(tid_to_user_info)}")
            print()
            
            for tid, user_info in tid_to_user_info.items():
                print(f"  Thread ID: {tid.value}")
                
                if user_info.has_username:
                    username = user_info.username.decode('utf-8', errors='ignore').rstrip('\x00')
                    print(f"    Username:      {username}")
                
                if user_info.has_cookie:
                    cookie = user_info.cookie.decode('utf-8', errors='ignore').rstrip('\x00')
                    print(f"    Cookie:        {cookie}")
                
                if user_info.has_authorization:
                    auth = user_info.authorization.decode('utf-8', errors='ignore').rstrip('\x00')
                    print(f"    Authorization: {auth}")
                
                print()
        
        print("=" * 80)
    
    def run(self):
        """Main execution"""
        print("=" * 80)
        print("HTTPS Server Sniffer - Clean Architecture")
        print("=" * 80)
        print("Initializing eBPF probes...")
        print()
        
        try:
            # Compile and load eBPF program
            self.bpf = BPF(text=bpf_text)
            
            # Attach to OpenSSL library
            ssl_lib = "/usr/lib/libssl.so.3"
            
            # Attach SSL_read probes
            try:
                self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read",
                                      fn_name="probe_ssl_read_enter")
                self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read",
                                         fn_name="probe_ssl_read_exit")
                print(f"✓ Attached to SSL_read")
            except Exception as e:
                print(f"⚠ Could not attach to SSL_read: {e}")
            
            # Attach SSL_read_ex probes
            try:
                self.bpf.attach_uprobe(name=ssl_lib, sym="SSL_read_ex",
                                      fn_name="probe_ssl_read_ex_enter")
                self.bpf.attach_uretprobe(name=ssl_lib, sym="SSL_read_ex",
                                         fn_name="probe_ssl_read_ex_exit")
                print(f"✓ Attached to SSL_read_ex")
            except Exception as e:
                print(f"⚠ Could not attach to SSL_read_ex: {e}")
            
            print()
            print("=" * 80)
            print("Monitoring HTTPS traffic...")
            print("Connection tracking: ON FIRST recv() per FD")
            print("Attribution: TID → FD → Connection (race-free!)")
            print("=" * 80)
            print()
            
            # Open perf buffer
            self.bpf["ssl_events"].open_perf_buffer(self.handle_ssl_event)
            
            # Poll for events
            while True:
                try:
                    self.bpf.perf_buffer_poll(timeout=100)
                except KeyboardInterrupt:
                    print("\n\nStopping sniffer...")
                    self.print_user_info_summary()
                    break
                    
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            raise


if __name__ == "__main__":
    import os
    
    if os.geteuid() != 0:
        print("This program must be run as root!")
        print("Usage: sudo python3 new_server_sniffer.py")
        exit(1)
    
    sniffer = HTTPSServerSniffer()
    sniffer.run()

