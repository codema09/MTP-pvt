#!/usr/bin/env python3
"""
HTTPS Server Sniffer using BCC eBPF
====================================
This program intercepts SSL/TLS decrypted data to capture HTTPS request headers
along with connection 4-tuple (src_ip, src_port, dst_ip, dst_port) and handling PID.

It hooks into OpenSSL's SSL_read function to capture decrypted HTTP data before
it reaches the application layer.

Usage: sudo python3 server-sniffer.py
"""

from bcc import BPF
import ctypes
import socket
import struct

# eBPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>

#define MAX_BUF_SIZE 2048
#define MAX_HEADER_SIZE 1024

// Structure to hold SSL connection data
struct ssl_data_t {
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 data_len;
    char data[MAX_HEADER_SIZE];
};

// BPF perf output
BPF_PERF_OUTPUT(ssl_events);

// Hash map to store SSL pointer to socket fd mapping
BPF_HASH(ssl_ctx_map, u64, u32);

// Hash map to store fd to connection info
struct conn_info_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};
BPF_HASH(fd_conn_map, u32, struct conn_info_t);

// Trace SSL_read to capture decrypted HTTPS data
int trace_ssl_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // Store SSL pointer for return probe
    u64 ssl_ptr = (u64)ssl;
    bpf_trace_printk("SSL_read called by PID: %d\\n", pid);
    
    return 0;
}

int trace_ssl_read_exit(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    int ret = PT_REGS_RC(ctx);
    
    // Only process successful reads
    if (ret <= 0) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // Allocate event structure
    struct ssl_data_t data = {};
    data.pid = pid;
    data.tid = tid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Read the decrypted buffer
    u32 copy_len = ret;
    if (copy_len > MAX_HEADER_SIZE) {
        copy_len = MAX_HEADER_SIZE;
    }
    
    bpf_probe_read_user(&data.data, copy_len & (MAX_HEADER_SIZE - 1), buf);
    data.data_len = copy_len;
    
    // Try to get connection info from socket
    // We'll need to get the socket from SSL structure
    // For now, we'll extract it from the current task's socket
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Submit event
    ssl_events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}

// Trace accept4/accept to capture connection info
int trace_accept_exit(struct pt_regs *ctx) {
    int fd = PT_REGS_RC(ctx);
    
    if (fd < 0) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    // Get socket information
    struct socket *sock = (struct socket *)PT_REGS_PARM1(ctx);
    
    bpf_trace_printk("Accept FD: %d, PID: %d\\n", fd, pid);
    
    return 0;
}

// Trace getpeername to capture connection info when socket operations happen
int trace_getpeername_enter(struct pt_regs *ctx, int fd) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    bpf_trace_printk("getpeername called for FD: %d by PID: %d\\n", fd, pid);
    
    return 0;
}
"""

# Extended eBPF program with kernel socket tracing
bpf_text_v2 = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/net.h>

#define MAX_BUF_SIZE 2048
#define MAX_HEADER_SIZE 1024

// Structure to hold SSL connection data with connection info
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

// BPF perf output
BPF_PERF_OUTPUT(ssl_events);

// Map to store fd -> connection info
struct conn_tuple_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

// Map socket FD to connection info (1-to-1 mapping!)
BPF_HASH(fd_to_conn, u32, struct conn_tuple_t);

// Map thread ID to socket FD it's currently using
BPF_HASH(tid_to_fd, u64, u32);

// BPF per-CPU array for temporary event storage (avoids stack memset issues)
BPF_PERCPU_ARRAY(event_storage, struct ssl_data_event_t, 1);

// Buffer to accumulate SSL reads per thread
struct buffer_t {
    char data[MAX_HEADER_SIZE];
    u32 len;
    u64 start_time;
};

BPF_HASH(read_buffers, u64, struct buffer_t);
BPF_HASH(read_enter_args, u64, void *);

// STEP 1: When accept4 returns, we need to capture both FD and connection info
// We'll use inet_csk_accept which has the socket struct
BPF_HASH(accept_fd_temp, u64, u32);  // Temporary: pid_tgid -> FD

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
    int fd = args->ret;
    
    if (fd < 0) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Store FD temporarily so inet_csk_accept can associate it with socket
    accept_fd_temp.update(&pid_tgid, &fd);
    
    return 0;
}

// For SSL_read: int SSL_read(SSL *ssl, void *buf, int num)
int probe_ssl_read_enter(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    read_enter_args.update(&pid_tgid, &buf);
    return 0;
}

int probe_ssl_read_exit(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    
    // Only process successful reads
    if (ret <= 0) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // Get the buffer pointer from enter probe
    void **buf_ptr = read_enter_args.lookup(&pid_tgid);
    if (buf_ptr == NULL) {
        return 0;
    }
    void *actual_buf = *buf_ptr;
    read_enter_args.delete(&pid_tgid);
    
    // Use per-CPU array to avoid memset issues
    u32 zero = 0;
    struct ssl_data_event_t *evt = event_storage.lookup(&zero);
    if (evt == NULL) {
        return 0;
    }
    
    evt->pid = pid;
    evt->tid = tid;
    evt->has_conn_info = 0;
    evt->src_ip = 0;
    evt->dst_ip = 0;
    evt->src_port = 0;
    evt->dst_port = 0;
    
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Read the decrypted buffer (ret = bytes read)
    u32 copy_len = ret;
    if (copy_len > MAX_HEADER_SIZE) {
        copy_len = MAX_HEADER_SIZE;
    }
    
    bpf_probe_read_user(&evt->data, copy_len & (MAX_HEADER_SIZE - 1), actual_buf);
    evt->data_len = copy_len;
    
    // STEP 4: Lookup connection via TID → FD → Connection (1-to-1 mapping!)
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
    
    // Submit ALL reads (we'll aggregate in Python)
    ssl_events.perf_submit(ctx, evt, sizeof(*evt));
    
    return 0;
}

// For SSL_read_ex: int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
// Store both buffer and readbytes pointer
struct read_ex_args_t {
    void *buf;
    void *readbytes_ptr;
};

BPF_HASH(read_ex_enter_args, u64, struct read_ex_args_t);

int probe_ssl_read_ex_enter(struct pt_regs *ctx, void *ssl, void *buf, unsigned long num, void *readbytes) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_ex_args_t args = {
        .buf = buf,
        .readbytes_ptr = readbytes,
    };
    read_ex_enter_args.update(&pid_tgid, &args);
    return 0;
}

int probe_ssl_read_ex_exit(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    
    // SSL_read_ex returns 1 on success, 0 on failure
    if (ret != 1) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    // Get the saved arguments
    struct read_ex_args_t *args = read_ex_enter_args.lookup(&pid_tgid);
    if (args == NULL) {
        return 0;
    }
    
    // Read the number of bytes that were read
    unsigned long bytes_read = 0;
    bpf_probe_read_user(&bytes_read, sizeof(bytes_read), args->readbytes_ptr);
    
    if (bytes_read <= 0) {
        read_ex_enter_args.delete(&pid_tgid);
        return 0;
    }
    
    void *actual_buf = args->buf;
    read_ex_enter_args.delete(&pid_tgid);
    
    // Use per-CPU array to avoid memset issues
    u32 zero = 0;
    struct ssl_data_event_t *evt = event_storage.lookup(&zero);
    if (evt == NULL) {
        return 0;
    }
    
    evt->pid = pid;
    evt->tid = tid;
    evt->has_conn_info = 0;
    evt->src_ip = 0;
    evt->dst_ip = 0;
    evt->src_port = 0;
    evt->dst_port = 0;
    
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Read the decrypted buffer
    u32 copy_len = bytes_read;
    if (copy_len > MAX_HEADER_SIZE) {
        copy_len = MAX_HEADER_SIZE;
    }
    
    bpf_probe_read_user(&evt->data, copy_len & (MAX_HEADER_SIZE - 1), actual_buf);
    evt->data_len = copy_len;
    
    // STEP 4: Lookup connection via TID → FD → Connection (1-to-1 mapping!)
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
    
    // Submit ALL reads (we'll aggregate in Python)
    ssl_events.perf_submit(ctx, evt, sizeof(*evt));
    
    return 0;
}

// STEP 2: inet_csk_accept has the socket struct with connection info
int trace_inet_csk_accept_exit(struct pt_regs *ctx) {
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    
    if (newsk == NULL) {
        return 0;
    }
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    u16 family = newsk->__sk_common.skc_family;
    if (family != AF_INET) {
        return 0;
    }
    
    // Get the FD that was just created by accept4
    u32 *fd_ptr = accept_fd_temp.lookup(&pid_tgid);
    if (fd_ptr == NULL) {
        return 0;  // No FD found, can't map
    }
    u32 fd = *fd_ptr;
    accept_fd_temp.delete(&pid_tgid);
    
    // Extract connection 4-tuple from socket
    struct conn_tuple_t conn = {
        .src_ip = newsk->__sk_common.skc_daddr,      // Remote client IP
        .dst_ip = newsk->__sk_common.skc_rcv_saddr,  // Local server IP
        .src_port = bpf_ntohs(newsk->__sk_common.skc_dport),  // Remote port
        .dst_port = newsk->__sk_common.skc_num,      // Local port (8443)
    };
    
    // KEY MAPPING: FD → Connection tuple (1-to-1!)
    fd_to_conn.update(&fd, &conn);
    
    bpf_trace_printk("Accept: FD=%d from %x:%d\\n", fd, conn.src_ip, conn.src_port);
    
    return 0;
}

// STEP 3: Track which thread is using which FD
// When a thread reads from an FD, record: TID → FD
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;
    
    // Check if this FD has connection info
    struct conn_tuple_t *conn = fd_to_conn.lookup(&fd);
    if (conn != NULL) {
        // This thread is now handling this FD
        tid_to_fd.update(&pid_tgid, &fd);
    }
    
    return 0;
}

// Also track recvfrom (SSL might use this)
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 fd = (u32)args->fd;
    
    struct conn_tuple_t *conn = fd_to_conn.lookup(&fd);
    if (conn != NULL) {
        tid_to_fd.update(&pid_tgid, &fd);
    }
    
    return 0;
}
"""

class SSLSniffer:
    def __init__(self):
        self.bpf = None
        self.request_buffers = {}  # tid -> {data, conn_info, pid, comm}
        self.last_cleanup = 0
        
    def ip_to_str(self, ip):
        """Convert IP integer to string format"""
        return socket.inet_ntoa(struct.pack("I", ip))
    
    def parse_http_headers(self, data):
        """Parse HTTP headers from raw data"""
        try:
            # Decode bytes to string
            text = data.decode('utf-8', errors='ignore')
            
            # Find the end of headers (double newline)
            header_end = text.find('\r\n\r\n')
            if header_end == -1:
                header_end = text.find('\n\n')
                if header_end == -1:
                    header_end = len(text)
            
            headers = text[:header_end]
            return headers
        except Exception as e:
            return f"[Error parsing headers: {e}]"
    
    def print_event(self, cpu, data, size):
        """Callback for processing SSL events"""
        import time
        event = self.bpf["ssl_events"].event(data)
        
        # Extract data
        data_bytes = bytes(event.data[:event.data_len])
        tid = event.tid
        
        # Initialize buffer for this TID if needed
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
        
        # Append data
        self.request_buffers[tid]['data'] += data_bytes
        
        # Update connection info if available
        if event.has_conn_info:
            self.request_buffers[tid]['has_conn_info'] = True
            self.request_buffers[tid]['src_ip'] = event.src_ip
            self.request_buffers[tid]['dst_ip'] = event.dst_ip
            self.request_buffers[tid]['src_port'] = event.src_port
            self.request_buffers[tid]['dst_port'] = event.dst_port
        
        # Check if we have a complete HTTP request (ends with \r\n\r\n or \n\n)
        full_data = self.request_buffers[tid]['data']
        if b'\r\n\r\n' in full_data or b'\n\n' in full_data:
            # Check if it's an HTTP request
            if (full_data.startswith(b'GET') or 
                full_data.startswith(b'POST') or 
                full_data.startswith(b'PUT') or
                full_data.startswith(b'DELETE') or
                full_data.startswith(b'HEAD') or
                full_data.startswith(b'OPTIONS') or
                full_data.startswith(b'PATCH')):
                
                req = self.request_buffers[tid]
                
                print("=" * 80)
                print(f"[HTTPS REQUEST INTERCEPTED]")
                print(f"PID: {req['pid']}")
                print(f"TID: {req['tid']}")
                print(f"Process: {req['comm']}")
                
                if req['has_conn_info']:
                    src_ip = self.ip_to_str(req['src_ip'])
                    dst_ip = self.ip_to_str(req['dst_ip'])
                    print(f"\nConnection 4-tuple:")
                    print(f"  Source:      {src_ip}:{req['src_port']}")
                    print(f"  Destination: {dst_ip}:{req['dst_port']}")
                else:
                    print(f"\nConnection info: [Tracking in progress...]")
                
                # Parse and print HTTP headers
                headers = self.parse_http_headers(full_data)
                print(f"\nHTTP Headers:")
                print("-" * 80)
                print(headers)
                print("-" * 80)
                print()
            
            # Clear buffer for this TID
            del self.request_buffers[tid]
        
        # Periodic cleanup of old buffers (older than 5 seconds)
        now = time.time()
        if now - self.last_cleanup > 5:
            self.last_cleanup = now
            expired_tids = [t for t, req in self.request_buffers.items() 
                           if now - req['timestamp'] > 5]
            for t in expired_tids:
                del self.request_buffers[t]
    
    def run(self):
        """Main execution function"""
        print("HTTPS Server Sniffer - BCC eBPF")
        print("=" * 80)
        print("Initializing eBPF probes...")
        
        # Load BPF program
        try:
            self.bpf = BPF(text=bpf_text_v2)
            
            # Attach to OpenSSL functions - use the full path for Python's SSL library
            ssl_lib_path = "/usr/lib/libssl.so.3"
            
            # Attach uprobes for SSL_read
            try:
                self.bpf.attach_uprobe(name=ssl_lib_path, sym="SSL_read", 
                                      fn_name="probe_ssl_read_enter")
                self.bpf.attach_uretprobe(name=ssl_lib_path, sym="SSL_read", 
                                         fn_name="probe_ssl_read_exit")
                print(f"✓ Attached to SSL_read ({ssl_lib_path})")
            except Exception as e:
                print(f"⚠ Could not attach to SSL_read: {e}")
            
            # Attach uprobes for SSL_read_ex (different signature)
            try:
                self.bpf.attach_uprobe(name=ssl_lib_path, sym="SSL_read_ex", 
                                      fn_name="probe_ssl_read_ex_enter")
                self.bpf.attach_uretprobe(name=ssl_lib_path, sym="SSL_read_ex", 
                                         fn_name="probe_ssl_read_ex_exit")
                print(f"✓ Attached to SSL_read_ex ({ssl_lib_path})")
            except Exception as e:
                print(f"⚠ Could not attach to SSL_read_ex: {e}")
            
            # Attach to kernel functions for connection tracking
            try:
                self.bpf.attach_kretprobe(event="inet_csk_accept", 
                                         fn_name="trace_inet_csk_accept_exit")
                print("✓ Attached to inet_csk_accept (connection tracking)")
            except Exception as e:
                print(f"⚠ Warning: Could not attach to inet_csk_accept: {e}")
            
            print("\n" + "=" * 80)
            print("Monitoring HTTPS traffic...")
            print("Press Ctrl+C to stop")
            print("Waiting for SSL_read calls from HTTPS connections...")
            print("=" * 80)
            print()
            
            # Open perf buffer
            self.bpf["ssl_events"].open_perf_buffer(self.print_event)
            
            # Poll for events
            while True:
                try:
                    self.bpf.perf_buffer_poll(timeout=100)
                except KeyboardInterrupt:
                    print("\n\nStopping sniffer...")
                    break
                    
        except Exception as e:
            print(f"Error initializing BPF: {e}")
            raise

if __name__ == "__main__":
    import os
    
    if os.geteuid() != 0:
        print("This program must be run as root (use sudo)")
        exit(1)
    
    sniffer = SSLSniffer()
    sniffer.run()

"""
╰─ ❯❯ curl -k   -H "User-Agent: MyCustomAgent/1.0"   -H "X-Custom-Header: custom_value"
   -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"   -b "session=xyz789" 
     https://localhost:8443

"""