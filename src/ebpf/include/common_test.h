// ═══════════════════════════════════════════════════════════════
// common.h — Kernel includes, constants, and data structures
// ═══════════════════════════════════════════════════════════════

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

#define NUM_CPUS __NUM_CPUS__

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
    u64 cpu_cycles_start; // legacy
    u64 cpu_cycles_end;   // legacy
    u64 cpu_cycles_used;  // legacy
    u32 memory_kb;
    u64 system_overhead_ns;
    u64 thread_lifetime_ns;
    u64 mmap_bytes;
    u64 mprotect_bytes;
    u64 peak_physical_bytes;
    u8 is_complete;
    u32 src_ip;
    u16 src_port;
    u32 dst_ip;
    u16 dst_port;
    u64 bytes_sent;
    u64 bytes_recv;
    u64 disk_read_bytes;
    u64 disk_write_bytes;

    // CPU METRICS
    u64 cpu_burst_total_ns;
    u32 cpu_burst_count;
    u64 cpu_cycles_total;
    u64 cpu_instructions_total;
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

struct cpu_burst_start_t {
    u64 ts;
    u64 cycles;
    u64 instructions;
};

struct pre_assign_cpu_t {
    u64 total_ns;
    u64 cycles;
    u64 instructions;
    u32 burst_count;
};

struct cpu_burst_event_t {
    u32  tid;
    u64  burst_ns;
    u64  cycles;
    u64  instructions;
    u8   has_request_id;
    char request_id[MAX_REQUEST_ID_LEN];
};

struct tcp_connect_args_t {
    u32 fd;
    u32 dst_ip;
    u16 dst_port;
};

struct conn_event_t {
    u32 tid;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

// ═══════════════════════════════════════════════════════════════
// THRIFT PROTOCOL INTERCEPTION (for DeathStarBench / plain-TCP RPC)
// ═══════════════════════════════════════════════════════════════

#define THRIFT_CAPTURE_SIZE 256

// Saved at sys_enter_recvfrom / sys_enter_read so the exit handler
// can read the user buffer and check for the Thrift magic bytes.
struct thrift_recv_args_t {
    u32 fd;
    void *buf;
};

// Sent to userspace for every recv() that begins with a valid Thrift
// strict-binary framed (or unframed) message header.
struct thrift_event_t {
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  has_conn_info;
    u8  has_request_id;
    u8  _pad[2];
    char request_id[MAX_REQUEST_ID_LEN];
    u32 data_len;
    u8  data[THRIFT_CAPTURE_SIZE];
};
