from bcc import BPF
from time import sleep

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <net/sock.h>

struct user_msghdr_local {
    void *msg_name;
    int msg_namelen;
    int __pad1;
    void *msg_iov;
    unsigned long msg_iovlen;
    void *msg_control;
    unsigned long msg_controllen;
    unsigned int msg_flags;
};

struct iovec_local {
    void *iov_base;
    unsigned long iov_len;
};

struct evt_t {
    u32 pid;
    u64 iov0_len;
    u64 iov1_len;
    u8 bytes0[8];
    u8 bytes1[8];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
    u32 fd = args->fd;
    if (fd <= 2) return 0;
    
    struct user_msghdr_local msg;
    if (bpf_probe_read_user(&msg, sizeof(msg), (void *)args->msg) != 0) return 0;
    
    if (msg.msg_iovlen == 0 || msg.msg_iovlen > 4) return 0;
    
    struct iovec_local iov[2];
    if (bpf_probe_read_user(&iov, sizeof(iov), (void *)msg.msg_iov) != 0) return 0;
    
    struct evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.iov0_len = iov[0].iov_len;
    evt.iov1_len = (msg.msg_iovlen >= 2) ? iov[1].iov_len : 0;
    
    if (evt.iov0_len > 0) bpf_probe_read_user(&evt.bytes0, 8, iov[0].iov_base);
    if (evt.iov1_len > 0) bpf_probe_read_user(&evt.bytes1, 8, iov[1].iov_base);
    
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

b = BPF(text=bpf_text)

print("Tracing sendmsg iovecs... Hit Ctrl-C to end")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    hex0 = " ".join([f"{x:02x}" for x in event.bytes0])
    hex1 = " ".join([f"{x:02x}" for x in event.bytes1])
    print(f"PID {event.pid}: iov[0] len={event.iov0_len} bytes=[{hex0}] | iov[1] len={event.iov1_len} bytes=[{hex1}]")

b["events"].open_perf_buffer(print_event)

try:
    # process events for 5 seconds
    for _ in range(50):
        b.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass
